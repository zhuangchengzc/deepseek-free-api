import { PassThrough } from "stream";
import _ from "lodash";
import axios, { AxiosResponse } from "axios";

import APIException from "@/lib/exceptions/APIException.ts";
import EX from "@/api/consts/exceptions.ts";
import { createParser } from "eventsource-parser";
import { DeepSeekHash } from "@/lib/challenge.ts";
import logger from "@/lib/logger.ts";
import util from "@/lib/util.ts";

// 模型名称
const MODEL_NAME = "deepseek-chat";
// 插冷鸡WASM文件路径
const WASM_PATH = './sha3_wasm_bg.7b9ca65ddd.wasm';
// access_token有效期
const ACCESS_TOKEN_EXPIRES = 3600;
// 最大重试次数
const MAX_RETRY_COUNT = 3;
// 重试延迟
const RETRY_DELAY = 5000;
// 伪装headers
const FAKE_HEADERS = {
  Accept: "*/*",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
  Origin: "https://chat.deepseek.com",
  Pragma: "no-cache",
  Priority: "u=1, i",
  Referer: "https://chat.deepseek.com/",
  "Sec-Ch-Ua":
    '"Chromium";v="133", "Google Chrome";v="133", "Not?A_Brand";v="99"',
  "Sec-Ch-Ua-Mobile": "?0",
  "Sec-Ch-Ua-Platform": '"Windows"',
  "Sec-Fetch-Dest": "empty",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Site": "same-origin",
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
  "X-App-Version": "20241129.1",
  "X-Client-Locale": "zh-CN",
  "X-Client-Platform": "web",
  "X-Client-Version": "1.0.0-always",
};
const EVENT_COMMIT_ID = '41e9c7b1';
// 当前IP地址
let ipAddress = '';
// access_token映射
const accessTokenMap = new Map();
// access_token请求队列映射
const accessTokenRequestQueueMap: Record<string, Function[]> = {};

async function getIPAddress() {
  if (ipAddress) return ipAddress;
  const result = await axios.get('https://chat.deepseek.com/', {
    headers: {
      ...FAKE_HEADERS,
      Cookie: generateCookie()
    },
    timeout: 15000,
    validateStatus: () => true,
  });
  const ip = result.data.match(/<meta name="ip" content="([\d.]+)">/)?.[1];
  if (!ip) throw new APIException(EX.API_REQUEST_FAILED, '获取IP地址失败');
  logger.info(`当前IP地址: ${ip}`);
  ipAddress = ip;
  return ip;
}

/**
 * 请求access_token
 *
 * 使用refresh_token去刷新获得access_token
 *
 * @param refreshToken 用于刷新access_token的refresh_token
 */
async function requestToken(refreshToken: string) {
  if (accessTokenRequestQueueMap[refreshToken])
    return new Promise((resolve) =>
      accessTokenRequestQueueMap[refreshToken].push(resolve)
    );
  accessTokenRequestQueueMap[refreshToken] = [];
  logger.info(`Refresh token: ${refreshToken}`);
  const result = await (async () => {
    const result = await axios.get(
      "https://chat.deepseek.com/api/v0/users/current",
      {
        headers: {
          Authorization: `Bearer ${refreshToken}`,
          ...FAKE_HEADERS,
        },
        timeout: 15000,
        validateStatus: () => true,
      }
    );
    const checkResultData = checkResult(result, refreshToken);
    const token = checkResultData?.biz_data?.token || checkResultData?.token;
    return {
      accessToken: token,
      refreshToken: token,
      refreshTime: util.unixTimestamp() + ACCESS_TOKEN_EXPIRES,
    };
  })()
    .then((result) => {
      if (accessTokenRequestQueueMap[refreshToken]) {
        accessTokenRequestQueueMap[refreshToken].forEach((resolve) =>
          resolve(result)
        );
        delete accessTokenRequestQueueMap[refreshToken];
      }
      logger.success(`Refresh successful`);
      return result;
    })
    .catch((err) => {
      if (accessTokenRequestQueueMap[refreshToken]) {
        accessTokenRequestQueueMap[refreshToken].forEach((resolve) =>
          resolve(err)
        );
        delete accessTokenRequestQueueMap[refreshToken];
      }
      return err;
    });
  if (_.isError(result)) throw result;
  return result;
}

/**
 * 获取缓存中的access_token
 *
 * 避免短时间大量刷新token，未加锁，如果有并发要求还需加锁
 *
 * @param refreshToken 用于刷新access_token的refresh_token
 */
async function acquireToken(refreshToken: string): Promise<string> {
  let result = accessTokenMap.get(refreshToken);
  if (!result) {
    result = await requestToken(refreshToken);
    accessTokenMap.set(refreshToken, result);
  }
  if (util.unixTimestamp() > result.refreshTime) {
    result = await requestToken(refreshToken);
    accessTokenMap.set(refreshToken, result);
  }
  return result.accessToken;
}

/**
 * 生成cookie
 */
function generateCookie() {
  return `intercom-HWWAFSESTIME=${util.timestamp()}; HWWAFSESID=${util.generateRandomString({
    charset: 'hex',
    length: 18
  })}; Hm_lvt_${util.uuid(false)}=${util.unixTimestamp()},${util.unixTimestamp()},${util.unixTimestamp()}; Hm_lpvt_${util.uuid(false)}=${util.unixTimestamp()}; _frid=${util.uuid(false)}; _fr_ssid=${util.uuid(false)}; _fr_pvid=${util.uuid(false)}`
}

async function createSession(model: string, refreshToken: string): Promise<string> {
  const token = await acquireToken(refreshToken);
  const result = await axios.post(
    "https://chat.deepseek.com/api/v0/chat_session/create",
    {
      character_id: null
    },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        ...FAKE_HEADERS,
      },
      timeout: 15000,
      validateStatus: () => true,
    }
  );
  const { biz_data } = checkResult(result, refreshToken);
  if (!biz_data)
    throw new APIException(EX.API_REQUEST_FAILED, "创建会话失败，可能是账号或IP地址被封禁");
  return biz_data.id;
}

/**
 * 删除会话
 * 
 * @param sessionId 会话ID
 * @param refreshToken 用于刷新access_token的refresh_token
 */
async function deleteSession(sessionId: string, refreshToken: string): Promise<void> {
  try {
    const token = await acquireToken(refreshToken);
    const result = await axios.post(
      "https://chat.deepseek.com/api/v0/chat_session/delete",
      {
        chat_session_id: sessionId
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          ...FAKE_HEADERS,
          Cookie: generateCookie()
        },
        timeout: 15000,
        validateStatus: () => true,
      }
    );
    checkResult(result, refreshToken);
    logger.info(`会话已删除: ${sessionId}`);
  } catch (err) {
    logger.error(`删除会话失败: ${sessionId}`, err);
  }
}

/**
 * 碰撞challenge答案
 * 
 * 厂商这个反逆向的策略不错哦
 * 相当于把计算量放在浏览器侧的话，用户分摊了这个计算量
 * 但是如果逆向在服务器上算，那这个成本都在服务器集中，并发一高就GG
 */
async function answerChallenge(response: any, targetPath: string): Promise<any> {
  const { algorithm, challenge, salt, difficulty, expire_at, signature } = response;
  const deepSeekHash = new DeepSeekHash();
  await deepSeekHash.init(WASM_PATH);
  const answer = deepSeekHash.calculateHash(algorithm, challenge, salt, difficulty, expire_at);
  return Buffer.from(JSON.stringify({
    algorithm,
    challenge,
    salt,
    answer,
    signature,
    target_path: targetPath
  })).toString('base64');
}

/**
 * 获取challenge响应
 *
 * @param refreshToken 用于刷新access_token的refresh_token
 */
async function getChallengeResponse(refreshToken: string, targetPath: string) {
  const token = await acquireToken(refreshToken);
  const result = await axios.post('https://chat.deepseek.com/api/v0/chat/create_pow_challenge', {
    target_path: targetPath
  }, {
    headers: {
      Authorization: `Bearer ${token}`,
      ...FAKE_HEADERS,
      Cookie: generateCookie()
    },
    timeout: 15000,
    validateStatus: () => true,
  });
  const { biz_data: { challenge } } = checkResult(result, refreshToken);
  return challenge;
}

/**
 * 同步对话补全
 *
 * @param model 模型名称
 * @param messages 参考gpt系列消息格式，多轮对话请完整提供上下文
 * @param refreshToken 用于刷新access_token的refresh_token
 * @param refConvId 引用对话ID
 * @param retryCount 重试次数
 * @param tools 工具列表
 * @param toolChoice 工具选择策略
 */
async function createCompletion(
  model = MODEL_NAME,
  messages: any[],
  refreshToken: string,
  refConvId?: string,
  retryCount = 0,
  tools?: any[],
  toolChoice?: any
) {
  return (async () => {
    logger.info(messages);

    // 如果引用对话ID不正确则重置引用
    if (!/[0-9a-z\-]{36}@[0-9]+/.test(refConvId))
      refConvId = null;

    // 消息预处理
    const prompt = messagesPrepare(messages, tools);

    // 解析引用对话ID
    const [refSessionId, refParentMsgId] = refConvId?.split('@') || [];

    // 创建会话
    const sessionId = refSessionId || await createSession(model, refreshToken);
    // 请求流
    const token = await acquireToken(refreshToken);

    const isSearchModel = model.includes('search') || prompt.includes('联网搜索');
    const isThinkingModel = model.includes('think') || model.includes('r1') || prompt.includes('深度思考');
    
    // 处理工具调用
    const hasTools = tools && tools.length > 0;

    // 已经支持同时使用，此处注释
    // if(isSearchModel && isThinkingModel)
    //   throw new APIException(EX.API_REQUEST_FAILED, '深度思考和联网搜索不能同时使用');

    if (isThinkingModel) {
      const thinkingQuota = await getThinkingQuota(refreshToken);
      if (thinkingQuota <= 0) {
        throw new APIException(EX.API_REQUEST_FAILED, '深度思考配额不足');
      }
    }

    const challengeResponse = await getChallengeResponse(refreshToken, '/api/v0/chat/completion');
    const challenge = await answerChallenge(challengeResponse, '/api/v0/chat/completion');
    logger.info(`插冷鸡: ${challenge}`);

    // 构建请求体
    const requestBody: any = {
      chat_session_id: sessionId,
      parent_message_id: refParentMsgId || null,
      prompt,
      ref_file_ids: [],
      search_enabled: isSearchModel,
      thinking_enabled: isThinkingModel
    };

    // 添加工具调用参数
    if (hasTools) {
      requestBody.tools = tools.map(tool => ({
        type: 'function',
        function: {
          name: tool.function.name,
          description: tool.function.description || '',
          parameters: tool.function.parameters || {}
        }
      }));
      
      if (toolChoice) {
        if (toolChoice === 'auto' || toolChoice === 'none') {
          requestBody.tool_choice = toolChoice;
        } else if (typeof toolChoice === 'object' && toolChoice.type === 'function') {
          requestBody.tool_choice = {
            type: 'function',
            function: { name: toolChoice.function.name }
          };
        }
      }
    }

    const result = await axios.post(
      "https://chat.deepseek.com/api/v0/chat/completion",
      requestBody,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          ...FAKE_HEADERS,
          Cookie: generateCookie(),
          'X-Ds-Pow-Response': challenge
        },
        // 120秒超时
        timeout: 120000,
        validateStatus: () => true,
        responseType: "stream",
      }
    );

    // 发送事件，缓解被封号风险
    await sendEvents(sessionId, refreshToken);

    if (result.headers["content-type"].indexOf("text/event-stream") == -1) {
      result.data.on("data", buffer => logger.error(buffer.toString()));
      throw new APIException(
        EX.API_REQUEST_FAILED,
        `Stream response Content-Type invalid: ${result.headers["content-type"]}`
      );
    }

    const streamStartTime = util.timestamp();
    // 接收流为输出文本
    const answer = await receiveStream(model, result.data, sessionId, hasTools);
    logger.success(
      `Stream has completed transfer ${util.timestamp() - streamStartTime}ms`
    );

    // 如果启用了工具但返回空响应，重新请求（不带工具定义）
    if (hasTools && 
        (!answer.choices[0].message.tool_calls || answer.choices[0].message.tool_calls.length === 0) &&
        (!answer.choices[0].message.content || answer.choices[0].message.content.trim() === '')) {
      logger.warn('[createCompletion] 检测到空响应，重新请求（不带工具定义）');
      // 删除临时会话
      if (!refSessionId) {
        await deleteSession(sessionId, refreshToken);
      }
      // 递归调用，不传递 tools 参数
      return await createCompletion(model, messages, refreshToken, refConvId, retryCount);
    }

    // 如果是临时创建的会话（非引用会话），则删除
    if (!refSessionId) {
     await deleteSession(sessionId, refreshToken);
    }

    return answer;
  })().catch((err) => {
    if (retryCount < MAX_RETRY_COUNT) {
      logger.error(`Stream response error: ${err.stack}`);
      logger.warn(`Try again after ${RETRY_DELAY / 1000}s...`);
      return (async () => {
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY));
        return createCompletion(
          model,
          messages,
          refreshToken,
          refConvId,
          retryCount + 1,
          tools,
          toolChoice
        );
      })();
    }
    throw err;
  });
}

/**
 * 流式对话补全
 *
 * @param model 模型名称
 * @param messages 参考gpt系列消息格式，多轮对话请完整提供上下文
 * @param refreshToken 用于刷新access_token的refresh_token
 * @param refConvId 引用对话ID
 * @param retryCount 重试次数
 * @param tools 工具列表
 * @param toolChoice 工具选择策略
 */
async function createCompletionStream(
  model = MODEL_NAME,
  messages: any[],
  refreshToken: string,
  refConvId?: string,
  retryCount = 0,
  tools?: any[],
  toolChoice?: any
) {
  return (async () => {
    logger.info(messages);

    // 如果引用对话ID不正确则重置引用
    if (!/[0-9a-z\-]{36}@[0-9]+/.test(refConvId))
      refConvId = null;

    // 处理工具调用：如果有工具定义，先用非流式获取完整响应，再模拟流式输出
    const hasTools = tools && tools.length > 0;
    if (hasTools) {
      logger.info('[流式工具调用] 检测到工具定义，使用非流式模式获取响应后模拟流式输出');
      
      // 调用非流式接口获取完整响应
      const completion = await createCompletion(model, messages, refreshToken, refConvId, retryCount, tools, toolChoice);
      
      // 创建模拟的流式响应
      const transStream = new PassThrough();
      const created = util.unixTimestamp();
      
      // 发送初始消息
      transStream.write(`data: ${JSON.stringify({
        id: completion.id,
        model: completion.model,
        object: "chat.completion.chunk",
        choices: [{
          index: 0,
          delta: { role: "assistant", content: "" },
          finish_reason: null
        }],
        created
      })}\n\n`);
      
      const choice = completion.choices[0];
      
      // 如果既没有工具调用也没有内容，重新请求（不带工具定义）
      if ((!choice.message.tool_calls || choice.message.tool_calls.length === 0) && 
          (!choice.message.content || choice.message.content.trim() === '')) {
        logger.warn('[流式工具调用] 模型返回空响应，重新创建会话（不带工具定义）');
        // 递归调用，但不传递 tools 参数
        return await createCompletionStream(model, messages, refreshToken, refConvId, retryCount);
      }
      
      // 如果有工具调用，发送工具调用信息
      if (choice.message.tool_calls && choice.message.tool_calls.length > 0) {
        for (const toolCall of choice.message.tool_calls) {
          transStream.write(`data: ${JSON.stringify({
            id: completion.id,
            model: completion.model,
            object: "chat.completion.chunk",
            choices: [{
              index: 0,
              delta: {
                tool_calls: [{
                  index: 0,
                  id: toolCall.id,
                  type: toolCall.type,
                  function: {
                    name: toolCall.function.name,
                    arguments: toolCall.function.arguments
                  }
                }]
              },
              finish_reason: null
            }],
            created
          })}\n\n`);
        }
      }
      
      // 如果有内容，分块发送（模拟打字效果）
      if (choice.message.content) {
        const content = choice.message.content;
        const chunkSize = 5; // 每次发送5个字符
        for (let i = 0; i < content.length; i += chunkSize) {
          const chunk = content.substring(i, i + chunkSize);
          transStream.write(`data: ${JSON.stringify({
            id: completion.id,
            model: completion.model,
            object: "chat.completion.chunk",
            choices: [{
              index: 0,
              delta: { content: chunk },
              finish_reason: null
            }],
            created
          })}\n\n`);
        }
      }
      
      // 发送结束标记
      transStream.write(`data: ${JSON.stringify({
        id: completion.id,
        model: completion.model,
        object: "chat.completion.chunk",
        choices: [{
          index: 0,
          delta: {},
          finish_reason: choice.finish_reason
        }],
        created
      })}\n\n`);
      
      transStream.end("data: [DONE]\n\n");
      
      logger.success('[流式工具调用] 模拟流式输出完成');
      return transStream;
    }

    // 原有的流式处理逻辑（无工具调用时）
    // 消息预处理
    const prompt = messagesPrepare(messages, tools);

    // 解析引用对话ID
    const [refSessionId, refParentMsgId] = refConvId?.split('@') || [];

    const isSearchModel = model.includes('search') || prompt.includes('联网搜索');
    const isThinkingModel = model.includes('think') || model.includes('r1') || prompt.includes('深度思考');

    // 已经支持同时使用，此处注释
    // if(isSearchModel && isThinkingModel)
    //   throw new APIException(EX.API_REQUEST_FAILED, '深度思考和联网搜索不能同时使用');

    if (isThinkingModel) {
      const thinkingQuota = await getThinkingQuota(refreshToken);
      if (thinkingQuota <= 0) {
        throw new APIException(EX.API_REQUEST_FAILED, '深度思考配额不足');
      }
    }

    const challengeResponse = await getChallengeResponse(refreshToken, '/api/v0/chat/completion');
    const challenge = await answerChallenge(challengeResponse, '/api/v0/chat/completion');
    logger.info(`插冷鸡: ${challenge}`);

    // 创建会话
    const sessionId = refSessionId || await createSession(model, refreshToken);
    // 请求流
    const token = await acquireToken(refreshToken);

    // 构建请求体
    const requestBody: any = {
      chat_session_id: sessionId,
      parent_message_id: refParentMsgId || null,
      prompt,
      ref_file_ids: [],
      search_enabled: isSearchModel,
      thinking_enabled: isThinkingModel
    };

    // 添加工具调用参数
    if (hasTools) {
      requestBody.tools = tools.map(tool => ({
        type: 'function',
        function: {
          name: tool.function.name,
          description: tool.function.description || '',
          parameters: tool.function.parameters || {}
        }
      }));
      
      if (toolChoice) {
        if (toolChoice === 'auto' || toolChoice === 'none') {
          requestBody.tool_choice = toolChoice;
        } else if (typeof toolChoice === 'object' && toolChoice.type === 'function') {
          requestBody.tool_choice = {
            type: 'function',
            function: { name: toolChoice.function.name }
          };
        }
      }
    }

    const result = await axios.post(
      "https://chat.deepseek.com/api/v0/chat/completion",
      requestBody,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          ...FAKE_HEADERS,
          Cookie: generateCookie(),
          'X-Ds-Pow-Response': challenge
        },
        // 120秒超时
        timeout: 120000,
        validateStatus: () => true,
        responseType: "stream",
      }
    );

    // 发送事件，缓解被封号风险
    await sendEvents(sessionId, refreshToken);

    if (result.headers["content-type"].indexOf("text/event-stream") == -1) {
      logger.error(
        `Invalid response Content-Type:`,
        result.headers["content-type"]
      );
      result.data.on("data", buffer => logger.error(buffer.toString()));
      const transStream = new PassThrough();
      transStream.end(
        `data: ${JSON.stringify({
          id: "",
          model: MODEL_NAME,
          object: "chat.completion.chunk",
          choices: [
            {
              index: 0,
              delta: {
                role: "assistant",
                content: "服务暂时不可用，第三方响应错误",
              },
              finish_reason: "stop",
            },
          ],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          created: util.unixTimestamp(),
        })}\n\n`
      );
      return transStream;
    }
    const streamStartTime = util.timestamp();
    // 创建转换流将消息格式转换为gpt兼容格式
    return createTransStream(model, result.data, sessionId, hasTools, async () => {
      logger.success(
        `Stream has completed transfer ${util.timestamp() - streamStartTime}ms`
      );

      // 如果是临时创建的会话（非引用会话），则删除
      if (!refSessionId) {
      await deleteSession(sessionId, refreshToken);
      }
    });
  })().catch((err) => {
    if (retryCount < MAX_RETRY_COUNT) {
      logger.error(`Stream response error: ${err.stack}`);
      logger.warn(`Try again after ${RETRY_DELAY / 1000}s...`);
      return (async () => {
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY));
        return createCompletionStream(
          model,
          messages,
          refreshToken,
          refConvId,
          retryCount + 1,
          tools,
          toolChoice
        );
      })();
    }
    throw err;
  });
}

/**
 * 消息预处理
 *
 * 由于接口只取第一条消息，此处会将多条消息合并为一条，实现多轮对话效果
 *
 * @param messages 参考gpt系列消息格式，多轮对话请完整提供上下文
 * @param tools 工具列表
 */
function messagesPrepare(messages: any[], tools?: any[]): string {
  // 处理消息内容
  const processedMessages = messages.map(message => {
    let text: string;
    if (Array.isArray(message.content)) {
      // 过滤出 type 为 "text" 的项并连接文本
      const texts = message.content
        .filter((item: any) => item.type === "text")
        .map((item: any) => item.text);
      text = texts.join('\n');
    } else {
      text = String(message.content);
    }
    return { role: message.role, text };
  });

  if (processedMessages.length === 0) return '';

  // 如果有工具定义，添加工具调用指令
  let toolInstruction = '';
  if (tools && tools.length > 0) {
    const toolDescriptions = tools.map(tool => {
      const func = tool.function;
      const params = func.parameters?.properties || {};
      const required = func.parameters?.required || [];
      
      const paramDesc = Object.keys(params).map(key => {
        const param = params[key];
        const isRequired = required.includes(key);
        return `  - ${key}${isRequired ? ' (必需)' : ' (可选)'}: ${param.type} - ${param.description || ''}`;
      }).join('\n');
      
      return `- ${func.name}: ${func.description || ''}\n${paramDesc ? '  参数:\n' + paramDesc : ''}`;
    }).join('\n\n');

    toolInstruction = `

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  CRITICAL: TOOL EXECUTION PROTOCOL  ⚠️
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

YOU CANNOT EXECUTE OPERATIONS DIRECTLY. You must use tools.

Available Tools:
${toolDescriptions}

MANDATORY RULES (NO EXCEPTIONS):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. ❌ FORBIDDEN: Never claim you have completed an action before calling the tool
   - DON'T say: "I have created the file"
   - DON'T say: "File successfully created"
   - DON'T say: "I've written to /opt/file.txt"

2. ✅ REQUIRED: When user requests an operation, you MUST output:
   TOOL_CALL: {"name": "tool_name", "arguments": {"param": "value"}}
   
3. ⏳ WAIT: After calling a tool, WAIT for the result before responding

4. 💬 ALLOWED: You can answer questions directly (no tool needed)

FORMAT REQUIREMENTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• TOOL_CALL must be on its own line
• JSON must be valid
• Use exact tool names from the list above

EXAMPLE (CORRECT):
User: "Create a file at /opt/test.txt"
You: TOOL_CALL: {"name": "write", "arguments": {"path": "/opt/test.txt", "content": "hello"}}

EXAMPLE (WRONG - DO NOT DO THIS):
User: "Create a file at /opt/test.txt"
You: "I have created the file at /opt/test.txt" ❌ FORBIDDEN!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

`;
  }

  // 合并连续相同角色的消息
  const mergedBlocks: { role: string; text: string }[] = [];
  let currentBlock = { ...processedMessages[0] };

  for (let i = 1; i < processedMessages.length; i++) {
    const msg = processedMessages[i];
    if (msg.role === currentBlock.role) {
      currentBlock.text += `\n\n${msg.text}`;
    } else {
      mergedBlocks.push(currentBlock);
      currentBlock = { ...msg };
    }
  }
  mergedBlocks.push(currentBlock);

  // 添加标签并连接结果
  let result = mergedBlocks
    .map((block, index) => {
      if (block.role === "assistant") {
        return `<｜Assistant｜>${block.text}<｜end▁of▁sentence｜>`;
      }
      
      if (block.role === "user" || block.role === "system") {
        return index > 0 ? `<｜User｜>${block.text}` : block.text;
      }

      return block.text;
    })
    .join('')
    .replace(/\!\[.+\]\(.+\)/g, "");

  // 将工具指令添加到第一个用户消息之后
  if (toolInstruction && mergedBlocks.length > 0) {
    result = mergedBlocks[0].text + toolInstruction + result.substring(mergedBlocks[0].text.length);
  }

  return result;
}

/**
 * 检查请求结果
 *
 * @param result 结果
 * @param refreshToken 用于刷新access_token的refresh_token
 */
function checkResult(result: AxiosResponse, refreshToken: string) {
  if (!result.data) return null;
  const { code, data, msg } = result.data;
  if (!_.isFinite(code)) return result.data;
  if (code === 0) return data;
  if (code == 40003) accessTokenMap.delete(refreshToken);
  throw new APIException(EX.API_REQUEST_FAILED, `[请求deepseek失败]: ${msg}`);
}

/**
 * 解析文本中的工具调用
 * 
 * @param text 文本内容
 * @returns 解析结果 { toolCalls: 工具调用数组, cleanedText: 清理后的文本 }
 */
function parseToolCallsFromText(text: string): { toolCalls: any[], cleanedText: string } {
  const toolCalls: any[] = [];
  let cleanedText = text;
  
  logger.info(`[parseToolCallsFromText] 输入文本: ${text.substring(0, 200)}`);
  
  // 查找所有 TOOL_CALL: 的位置
  const toolCallPrefix = 'TOOL_CALL:';
  let startIndex = 0;
  
  while ((startIndex = text.indexOf(toolCallPrefix, startIndex)) !== -1) {
    // 跳过 "TOOL_CALL:" 前缀
    let jsonStart = startIndex + toolCallPrefix.length;
    
    // 跳过空白字符
    while (jsonStart < text.length && /\s/.test(text[jsonStart])) {
      jsonStart++;
    }
    
    // 确保是 JSON 对象开始
    if (jsonStart >= text.length || text[jsonStart] !== '{') {
      startIndex = jsonStart;
      continue;
    }
    
    // 使用括号计数法找到完整的 JSON 对象
    let braceCount = 0;
    let jsonEnd = jsonStart;
    let inString = false;
    let escapeNext = false;
    
    for (let i = jsonStart; i < text.length; i++) {
      const char = text[i];
      
      if (escapeNext) {
        escapeNext = false;
        continue;
      }
      
      if (char === '\\') {
        escapeNext = true;
        continue;
      }
      
      if (char === '"') {
        inString = !inString;
        continue;
      }
      
      if (!inString) {
        if (char === '{') {
          braceCount++;
        } else if (char === '}') {
          braceCount--;
          if (braceCount === 0) {
            jsonEnd = i + 1;
            break;
          }
        }
      }
    }
    
    // 提取 JSON 字符串
    const jsonStr = text.substring(jsonStart, jsonEnd);
    const fullMatch = text.substring(startIndex, jsonEnd);
    
    logger.info(`[parseToolCallsFromText] 找到匹配: ${fullMatch.substring(0, 100)}...`);
    
    try {
      logger.info(`[parseToolCallsFromText] 尝试解析 JSON (长度: ${jsonStr.length})`);
      const toolCallData = JSON.parse(jsonStr);
      logger.info(`[parseToolCallsFromText] JSON 解析成功: ${JSON.stringify(toolCallData).substring(0, 200)}`);
      
      if (toolCallData.name && toolCallData.arguments !== undefined) {
        toolCalls.push({
          id: `call_${util.uuid(false)}`,
          type: 'function',
          function: {
            name: toolCallData.name,
            arguments: typeof toolCallData.arguments === 'string' 
              ? toolCallData.arguments 
              : JSON.stringify(toolCallData.arguments)
          }
        });
        // 从文本中移除工具调用标记
        cleanedText = cleanedText.replace(fullMatch, '').trim();
        logger.info(`[parseToolCallsFromText] 成功添加工具调用: ${toolCallData.name}`);
      } else {
        logger.warn(`[parseToolCallsFromText] 工具调用数据不完整: name=${toolCallData.name}, arguments=${toolCallData.arguments}`);
      }
    } catch (err) {
      logger.error(`[parseToolCallsFromText] JSON 解析失败: ${err.message}`);
      logger.error(`[parseToolCallsFromText] 失败的 JSON: ${jsonStr.substring(0, 200)}`);
    }
    
    // 移动到下一个可能的位置
    startIndex = jsonEnd > startIndex ? jsonEnd : startIndex + 1;
  }
  
  logger.info(`[parseToolCallsFromText] 总共解析出 ${toolCalls.length} 个工具调用`);
  
  return { toolCalls, cleanedText };
}

/**
 * 从流接收完整的消息内容
 *
 * @param model 模型名称
 * @param stream 消息流
 * @param refConvId 引用对话ID
 * @param hasTools 是否有工具调用
 */
async function receiveStream(model: string, stream: any, refConvId?: string, hasTools = false): Promise<any> {
  let thinking = false;
  const isSearchModel = model.includes('search');
  const isThinkingModel = model.includes('think') || model.includes('r1');
  const isSilentModel = model.includes('silent');
  const isFoldModel = model.includes('fold');
  logger.info(`模型: ${model}, 是否思考: ${isThinkingModel} 是否联网搜索: ${isSearchModel}, 是否静默思考: ${isSilentModel}, 是否折叠思考: ${isFoldModel}`);
  let refContent = '';
  return new Promise((resolve, reject) => {
    // 消息初始化
    const data = {
      id: "",
      model,
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: { 
            role: "assistant", 
            content: "", 
            reasoning_content: "",
            tool_calls: undefined as any[] | undefined
          },
          finish_reason: "stop",
        },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      created: util.unixTimestamp(),
    };
    
    // 工具调用相关
    let toolCalls: any[] = [];
    let currentToolCall: any = null;
    
    const parser = createParser((event) => {
      try {
        // 只处理没有特定 event 字段的事件（默认事件）
        if (event.type !== "event") return;
        if ((event as any).event && (event as any).event !== 'message') return;
        const eventData = (event as any).data;
        if (!eventData || eventData.trim() == "[DONE]") return;
        
        // 解析JSON
        const result = _.attempt(() => JSON.parse(eventData));
        if (_.isError(result))
          throw new Error(`Stream response invalid: ${eventData}`);
        
        // 新格式：处理 DeepSeek 的新 API 格式
        if (result.v !== undefined) {
          // 检查是否是内容更新
          if (result.p === 'response/content' || result.o === 'APPEND' || typeof result.v === 'string') {
            // 过滤掉 FINISHED 标记
            let content = result.v;
            if (typeof content === 'string') {
              content = content.replace(/FINISHED\s*$/i, '');
            }
            data.choices[0].message.content += content;
          }
          // 检查是否有 message_id
          if (result.response && result.response.message_id && !data.id) {
            data.id = `${refConvId}@${result.response.message_id}`;
          }
          return;
        }
        
        // 旧格式：兼容原有的 choices/delta 格式
        if (!result.choices || !result.choices[0] || !result.choices[0].delta)
          return;
        if (!data.id)
          data.id = `${refConvId}@${result.message_id}`;
        if (result.choices[0].delta.type === "search_result" && !isSilentModel) {
          const searchResults = result.choices[0]?.delta?.search_results || [];
          refContent += searchResults.map(item => `${item.title} - ${item.url}`).join('\n');
          return;
        }
        if (isFoldModel && result.choices[0].delta.type === "thinking") {
          if (!thinking && isThinkingModel && !isSilentModel) {
            thinking = true;
            data.choices[0].message.content += isFoldModel ? "<details><summary>思考过程</summary><pre>" : "[思考开始]\n";
          }
          if (isSilentModel)
            return;
        }
        else if (isFoldModel && thinking && isThinkingModel && !isSilentModel) {
          thinking = false;
          data.choices[0].message.content += isFoldModel ? "</pre></details>" : "\n\n[思考结束]\n";
        }
        if (result.choices[0].delta.content) {
          if(result.choices[0].delta.type === "thinking" && !isFoldModel){
            data.choices[0].message.reasoning_content += result.choices[0].delta.content;
          }else {
            data.choices[0].message.content += result.choices[0].delta.content;
          }
        }
        
        // 处理工具调用
        if (hasTools && result.choices[0].delta.tool_calls) {
          const deltaToolCalls = result.choices[0].delta.tool_calls;
          for (const deltaToolCall of deltaToolCalls) {
            if (deltaToolCall.index !== undefined) {
              // 新的工具调用或更新现有的
              if (!toolCalls[deltaToolCall.index]) {
                toolCalls[deltaToolCall.index] = {
                  id: deltaToolCall.id || `call_${util.uuid(false)}`,
                  type: 'function',
                  function: {
                    name: deltaToolCall.function?.name || '',
                    arguments: deltaToolCall.function?.arguments || ''
                  }
                };
              } else {
                // 追加参数
                if (deltaToolCall.function?.arguments) {
                  toolCalls[deltaToolCall.index].function.arguments += deltaToolCall.function.arguments;
                }
                if (deltaToolCall.function?.name) {
                  toolCalls[deltaToolCall.index].function.name = deltaToolCall.function.name;
                }
              }
            }
          }
        }
        
        if (result.choices && result.choices[0] && result.choices[0].finish_reason === "stop") {
          let finalContent = data.choices[0].message.content
            .replace(/^\n+/, '')
            .replace(/\[citation:\d+\]/g, '')
            .replace(/FINISHED\s*$/i, '')
            .trim();
          
          logger.info(`[工具调用] hasTools: ${hasTools}, toolCalls.length: ${toolCalls.length}`);
          logger.info(`[工具调用] finalContent: ${finalContent.substring(0, 200)}`);
          
          // 如果启用了工具调用，尝试从文本中解析工具调用
          if (hasTools && toolCalls.length === 0) {
            logger.info('[工具调用] 开始解析文本中的工具调用');
            const parsed = parseToolCallsFromText(finalContent);
            logger.info(`[工具调用] 解析结果: ${parsed.toolCalls.length} 个工具调用`);
            if (parsed.toolCalls.length > 0) {
              logger.info(`[工具调用] 工具调用详情: ${JSON.stringify(parsed.toolCalls)}`);
              toolCalls = parsed.toolCalls;
              finalContent = parsed.cleanedText;
            }
          }
          
          data.choices[0].message.content = finalContent + (refContent ? `\n\n搜索结果来自：\n${refContent}` : '');
          
          // 添加工具调用到消息中
          if (toolCalls.length > 0) {
            data.choices[0].message.tool_calls = toolCalls;
            data.choices[0].finish_reason = 'tool_calls';
            logger.success('[工具调用] 成功设置 tool_calls');
          }
          
          resolve(data);
        }
      } catch (err) {
        logger.error(err);
        reject(err);
      }
    });
    // 将流数据喂给SSE转换器
    stream.on("data", (buffer) => parser.feed(buffer.toString()));
    stream.once("error", (err) => reject(err));
    stream.once("close", () => {
      // 流结束时，如果启用了工具调用，尝试从文本中解析
      if (hasTools && toolCalls.length === 0) {
        logger.info(`[工具调用] 流结束，开始解析文本中的工具调用`);
        logger.info(`[工具调用] 最终内容: ${data.choices[0].message.content.substring(0, 300)}`);
        const parsed = parseToolCallsFromText(data.choices[0].message.content);
        if (parsed.toolCalls.length > 0) {
          logger.success(`[工具调用] 成功解析 ${parsed.toolCalls.length} 个工具调用`);
          toolCalls = parsed.toolCalls;
          data.choices[0].message.content = parsed.cleanedText;
          data.choices[0].message.tool_calls = toolCalls;
          data.choices[0].finish_reason = 'tool_calls';
        } else {
          logger.warn(`[工具调用] 未能解析出工具调用`);
        }
      }
      
      resolve(data);
    });
  });
}

/**
 * 创建转换流
 *
 * 将流格式转换为gpt兼容流格式
 *
 * @param model 模型名称
 * @param stream 消息流
 * @param refConvId 引用对话ID
 * @param hasTools 是否有工具调用
 * @param endCallback 传输结束回调
 */
function createTransStream(model: string, stream: any, refConvId: string, hasTools = false, endCallback?: Function) {
  let thinking = false;
  const isSearchModel = model.includes('search');
  const isThinkingModel = model.includes('think') || model.includes('r1');
  const isSilentModel = model.includes('silent');
  const isFoldModel = model.includes('fold');
  logger.info(`模型: ${model}, 是否思考: ${isThinkingModel}, 是否联网搜索: ${isSearchModel}, 是否静默思考: ${isSilentModel}, 是否折叠思考: ${isFoldModel}`);
  // 消息创建时间
  const created = util.unixTimestamp();
  // 创建转换流
  const transStream = new PassThrough();
  
  // 工具调用相关
  let toolCalls: any[] = [];
  let accumulatedContent = ''; // 累积的内容，用于解析工具调用
  
  !transStream.closed &&
    transStream.write(
      `data: ${JSON.stringify({
        id: "",
        model,
        object: "chat.completion.chunk",
        choices: [
          {
            index: 0,
            delta: { role: "assistant", content: "" , reasoning_content: "" },
            finish_reason: null,
          },
        ],
        created,
      })}\n\n`
    );
  const parser = createParser((event) => {
    try {
      // 只处理没有特定 event 字段的事件
      if (event.type !== "event") return;
      if ((event as any).event && (event as any).event !== 'message') return;
      const eventData = (event as any).data;
      if (!eventData || eventData.trim() == "[DONE]") return;
      
      // 解析JSON
      const result = _.attempt(() => JSON.parse(eventData));
      if (_.isError(result))
        throw new Error(`Stream response invalid: ${eventData}`);
      
      // 新格式：处理 DeepSeek 的新 API 格式
      if (result.v !== undefined) {
        // 检查是否是内容更新
        if (result.p === 'response/content' || result.o === 'APPEND' || typeof result.v === 'string') {
          // 过滤掉 FINISHED 标记
          let content = result.v;
          if (typeof content === 'string') {
            content = content.replace(/FINISHED\s*$/i, '');
          }
          transStream.write(`data: ${JSON.stringify({
            id: refConvId,
            model,
            object: "chat.completion.chunk",
            choices: [
              {
                index: 0,
                delta: { role: "assistant", content },
                finish_reason: null,
              },
            ],
            created,
          })}\n\n`);
        }
        // 检查是否完成
        if (result.response && result.response.status === 'DONE') {
          transStream.write(`data: ${JSON.stringify({
            id: refConvId,
            model,
            object: "chat.completion.chunk",
            choices: [
              {
                index: 0,
                delta: { role: "assistant", content: "" },
                finish_reason: "stop"
              },
            ],
            created,
          })}\n\n`);
          !transStream.closed && transStream.end("data: [DONE]\n\n");
          endCallback && endCallback();
        }
        return;
      }
      
      // 旧格式：兼容原有的 choices/delta 格式
      if (!result.choices || !result.choices[0] || !result.choices[0].delta)
        return;
      result.model = model;
      if (result.choices[0].delta.type === "search_result" && !isSilentModel) {
        const searchResults = result.choices[0]?.delta?.search_results || [];
        if (searchResults.length > 0) {
          const refContent = searchResults.map(item => `检索 ${item.title} - ${item.url}`).join('\n') + '\n\n';
          transStream.write(`data: ${JSON.stringify({
            id: `${refConvId}@${result.message_id}`,
            model: result.model,
            object: "chat.completion.chunk",
            choices: [
              {
                index: 0,
                delta: { role: "assistant", content: refContent },
                finish_reason: null,
              },
            ],
          })}\n\n`);
        }
        return;
      }
      if (isFoldModel && result.choices[0].delta.type === "thinking") {
        if (!thinking && isThinkingModel && !isSilentModel) {
          thinking = true;
          transStream.write(`data: ${JSON.stringify({
            id: `${refConvId}@${result.message_id}`,
            model: result.model,
            object: "chat.completion.chunk",
            choices: [
              {
                index: 0,
                delta: { role: "assistant", content: isFoldModel ? "<details><summary>思考过程</summary><pre>" : "[思考开始]\n" },
                finish_reason: null,
              },
            ],
            created,
          })}\n\n`);
        }
        if (isSilentModel)
          return;
      }
      else if (isFoldModel && thinking && isThinkingModel && !isSilentModel) {
        thinking = false;
        transStream.write(`data: ${JSON.stringify({
          id: `${refConvId}@${result.message_id}`,
          model: result.model,
          object: "chat.completion.chunk",
          choices: [
            {
              index: 0,
              delta: { role: "assistant", content: isFoldModel ? "</pre></details>" : "\n\n[思考结束]\n" },
              finish_reason: null,
            },
          ],
          created,
        })}\n\n`);
      }

      if (!result.choices[0].delta.content)
        return;

      const deltaContent = result.choices[0].delta.content.replace(/\[citation:\d+\]/g, '');
      
      // 累积内容用于工具调用检测
      if (hasTools) {
        accumulatedContent += deltaContent;
        
        // 检查是否包含完整的工具调用（支持嵌套 JSON）
        const toolCallMatch = accumulatedContent.match(/TOOL_CALL:\s*(\{(?:[^{}]|\{[^{}]*\})*\})/);
        if (toolCallMatch) {
          try {
            const toolCallData = JSON.parse(toolCallMatch[1]);
            if (toolCallData.name && toolCallData.arguments !== undefined) {
              const toolCall = {
                id: `call_${util.uuid(false)}`,
                type: 'function',
                function: {
                  name: toolCallData.name,
                  arguments: typeof toolCallData.arguments === 'string' 
                    ? toolCallData.arguments 
                    : JSON.stringify(toolCallData.arguments)
                }
              };
              toolCalls.push(toolCall);
              
              // 发送工具调用
              transStream.write(`data: ${JSON.stringify({
                id: `${refConvId}@${result.message_id}`,
                model: result.model,
                object: "chat.completion.chunk",
                choices: [
                  {
                    index: 0,
                    delta: {
                      tool_calls: [{
                        index: toolCalls.length - 1,
                        id: toolCall.id,
                        type: 'function',
                        function: {
                          name: toolCall.function.name,
                          arguments: toolCall.function.arguments
                        }
                      }]
                    },
                    finish_reason: null,
                  },
                ],
                created,
              })}\n\n`);
              
              // 清除已处理的工具调用部分
              accumulatedContent = accumulatedContent.replace(toolCallMatch[0], '').trim();
              return; // 不发送包含 TOOL_CALL 的内容
            }
          } catch (err) {
            // JSON 解析失败，继续累积
          }
        }
      }
      
      const delta = result.choices[0].delta.type === "thinking" && !isFoldModel
          ? { role: "assistant", reasoning_content: deltaContent }
          : { role: "assistant", content: deltaContent };

      transStream.write(`data: ${JSON.stringify({
        id: `${refConvId}@${result.message_id}`,
        model: result.model,
        object: "chat.completion.chunk",
        choices: [
          {
            index: 0,
            delta,
            finish_reason: null,
          },
        ],
        created,
      })}\n\n`);
      
      // 处理工具调用
      if (hasTools && result.choices[0].delta.tool_calls) {
        const deltaToolCalls = result.choices[0].delta.tool_calls;
        for (const deltaToolCall of deltaToolCalls) {
          if (deltaToolCall.index !== undefined) {
            // 新的工具调用或更新现有的
            if (!toolCalls[deltaToolCall.index]) {
              toolCalls[deltaToolCall.index] = {
                id: deltaToolCall.id || `call_${util.uuid(false)}`,
                type: 'function',
                function: {
                  name: deltaToolCall.function?.name || '',
                  arguments: deltaToolCall.function?.arguments || ''
                }
              };
            } else {
              // 追加参数
              if (deltaToolCall.function?.arguments) {
                toolCalls[deltaToolCall.index].function.arguments += deltaToolCall.function.arguments;
              }
              if (deltaToolCall.function?.name) {
                toolCalls[deltaToolCall.index].function.name = deltaToolCall.function.name;
              }
            }
            
            // 发送工具调用增量
            transStream.write(`data: ${JSON.stringify({
              id: `${refConvId}@${result.message_id}`,
              model: result.model,
              object: "chat.completion.chunk",
              choices: [
                {
                  index: 0,
                  delta: {
                    tool_calls: [{
                      index: deltaToolCall.index,
                      id: deltaToolCall.id,
                      type: 'function',
                      function: {
                        name: deltaToolCall.function?.name,
                        arguments: deltaToolCall.function?.arguments
                      }
                    }]
                  },
                  finish_reason: null,
                },
              ],
              created,
            })}\n\n`);
          }
        }
      }

      if (result.choices && result.choices[0] && result.choices[0].finish_reason === "stop") {
        // 在流式响应结束时，如果还有累积的内容未解析，尝试解析工具调用
        if (hasTools && toolCalls.length === 0 && accumulatedContent.trim()) {
          logger.info(`[流式工具调用] 结束时检查累积内容: ${accumulatedContent.substring(0, 200)}`);
          const toolCallMatch = accumulatedContent.match(/TOOL_CALL:\s*(\{(?:[^{}]|\{[^{}]*\})*\})/);
          if (toolCallMatch) {
            try {
              const toolCallData = JSON.parse(toolCallMatch[1]);
              if (toolCallData.name && toolCallData.arguments !== undefined) {
                const toolCall = {
                  id: `call_${util.uuid(false)}`,
                  type: 'function',
                  function: {
                    name: toolCallData.name,
                    arguments: typeof toolCallData.arguments === 'string' 
                      ? toolCallData.arguments 
                      : JSON.stringify(toolCallData.arguments)
                  }
                };
                toolCalls.push(toolCall);
                logger.success(`[流式工具调用] 在结束时成功解析工具调用: ${toolCallData.name}`);
                
                // 发送工具调用
                transStream.write(`data: ${JSON.stringify({
                  id: `${refConvId}@${result.message_id}`,
                  model: result.model,
                  object: "chat.completion.chunk",
                  choices: [
                    {
                      index: 0,
                      delta: {
                        tool_calls: [{
                          index: 0,
                          id: toolCall.id,
                          type: 'function',
                          function: {
                            name: toolCall.function.name,
                            arguments: toolCall.function.arguments
                          }
                        }]
                      },
                      finish_reason: null,
                    },
                  ],
                  created,
                })}\n\n`);
              }
            } catch (err) {
              logger.warn(`[流式工具调用] 结束时解析失败: ${err.message}`);
            }
          }
        }
        
        const finishReason = toolCalls.length > 0 ? 'tool_calls' : 'stop';
        logger.info(`[流式工具调用] 发送结束标记, finishReason: ${finishReason}, toolCalls: ${toolCalls.length}`);
        transStream.write(`data: ${JSON.stringify({
          id: `${refConvId}@${result.message_id}`,
          model: result.model,
          object: "chat.completion.chunk",
          choices: [
            {
              index: 0,
              delta: { role: "assistant", content: "" },
              finish_reason: finishReason
            },
          ],
          created,
        })}\n\n`);
        !transStream.closed && transStream.end("data: [DONE]\n\n");
        endCallback && endCallback();
      }
    } catch (err) {
      logger.error(err);
      !transStream.closed && transStream.end("data: [DONE]\n\n");
    }
  });
  // 将流数据喂给SSE转换器
  stream.on("data", (buffer) => parser.feed(buffer.toString()));
  stream.once(
    "error",
    () => !transStream.closed && transStream.end("data: [DONE]\n\n")
  );
  stream.once(
    "close",
    () => {
      !transStream.closed && transStream.end("data: [DONE]\n\n");
      endCallback && endCallback();
    }
  );
  return transStream;
}

/**
 * Token切分
 *
 * @param authorization 认证字符串
 */
function tokenSplit(authorization: string) {
  // Normalize: remove leading 'Bearer ', split by comma, trim, drop empties
  if (!authorization) return [];
  const normalized = authorization.replace(/^Bearer\s+/i, "");
  return normalized
    .split(",")
    .map((t: string) => t.trim())
    .filter((t: string) => t.length > 0);
}

/**
 * 获取Token存活状态
 */
async function getTokenLiveStatus(refreshToken: string) {
  const token = await acquireToken(refreshToken);
  const result = await axios.get(
    "https://chat.deepseek.com/api/v0/users/current",
    {
      headers: {
        Authorization: `Bearer ${token}`,
        ...FAKE_HEADERS,
        Cookie: generateCookie()
      },
      timeout: 15000,
      validateStatus: () => true,
    }
  );
  try {
    const { token } = checkResult(result, refreshToken);
    return !!token;
  }
  catch (err) {
    return false;
  }
}

async function sendEvents(refConvId: string, refreshToken: string) {
  try {
    const token = await acquireToken(refreshToken);
    const sessionId = `session_v0_${Math.random().toString(36).slice(2)}`;
    const timestamp = util.timestamp();
    const fakeDuration1 = Math.floor(Math.random() * 1000);
    const fakeDuration2 = Math.floor(Math.random() * 1000);
    const fakeDuration3 = Math.floor(Math.random() * 1000);
    const ipAddress = await getIPAddress();
    const response = await axios.post('https://chat.deepseek.com/api/v0/events', {
      "events": [
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp,
          "event_name": "__reportEvent",
          "event_message": "调用上报事件接口",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "method": "post",
            "url": "/api/v0/events",
            "path": "/api/v0/events"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 100 + Math.floor(Math.random() * 1000),
          "event_name": "__reportEventOk",
          "event_message": "调用上报事件接口成功",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "method": "post",
            "url": "/api/v0/events",
            "path": "/api/v0/events",
            "logId": util.uuid(),
            "metricDuration": Math.floor(Math.random() * 1000),
            "status": "200"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 200 + Math.floor(Math.random() * 1000),
          "event_name": "createSessionAndStartCompletion",
          "event_message": "开始创建对话",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "__referrer": "",
            "agentId": "chat",
            "thinkingEnabled": false
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 300 + Math.floor(Math.random() * 1000),
          "event_name": "__httpRequest",
          "event_message": "httpRequest POST /api/v0/chat_session/create",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "__referrer": "",
            "url": "/api/v0/chat_session/create",
            "path": "/api/v0/chat_session/create",
            "method": "POST"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 400 + Math.floor(Math.random() * 1000),
          "event_name": "__httpResponse",
          "event_message": `httpResponse POST /api/v0/chat_session/create, ${Math.floor(Math.random() * 1000)}ms, reason: none`,
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "url": "/api/v0/chat_session/create",
            "path": "/api/v0/chat_session/create",
            "method": "POST",
            "metricDuration": Math.floor(Math.random() * 1000),
            "status": "200",
            "logId": util.uuid()
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 500 + Math.floor(Math.random() * 1000),
          "event_name": "__log",
          "event_message": "使用 buffer 模式",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": ""
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 600 + Math.floor(Math.random() * 1000),
          "event_name": "chatCompletionApi",
          "event_message": "chatCompletionApi 被调用",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "scene": "completion",
            "chatSessionId": refConvId,
            "withFile": "false",
            "thinkingEnabled": "false"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 700 + Math.floor(Math.random() * 1000),
          "event_name": "__httpRequest",
          "event_message": "httpRequest POST /api/v0/chat/completion",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "url": "/api/v0/chat/completion",
            "path": "/api/v0/chat/completion",
            "method": "POST"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 800 + Math.floor(Math.random() * 1000),
          "event_name": "completionFirstChunkReceived",
          "event_message": "收到第一个 completion chunk（可以是空 chunk）",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "metricDuration": Math.floor(Math.random() * 1000),
            "logId": util.uuid()
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 900 + Math.floor(Math.random() * 1000),
          "event_name": "createSessionAndStartCompletion",
          "event_message": "创建会话并开始补全",
          "payload": {
            "__location": "https://chat.deepseek.com/",
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "agentId": "chat",
            "newSessionId": refConvId,
            "isCreateNewChat": "false",
            "thinkingEnabled": "false"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 1000 + Math.floor(Math.random() * 1000),
          "event_name": "routeChange",
          "event_message": `路由改变 => /a/chat/s/${refConvId}`,
          "payload": {
            "__location": `https://chat.deepseek.com/a/chat/s/${refConvId}`,
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "to": `/a/chat/s/${refConvId}`,
            "redirect": "false",
            "redirected": "false",
            "redirectReason": "",
            "redirectTo": "/",
            "hasToken": "true",
            "hasUserInfo": "true"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 1100 + Math.floor(Math.random() * 1000),
          "event_name": "__pageVisit",
          "event_message": `访问页面 [/a/chat/s/${refConvId}] [0]：${fakeDuration1}ms`,
          "payload": {
            "__location": `https://chat.deepseek.com/a/chat/s/${refConvId}`,
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "pathname": `/a/chat/s/${refConvId}`,
            "metricVisitIndex": 0,
            "metricDuration": fakeDuration1,
            "referrer": "none",
            "appTheme": "light"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 1200 + Math.floor(Math.random() * 1000),
          "event_name": "__tti",
          "event_message": `/a/chat/s/${refConvId} TTI 上报：${fakeDuration2}ms`,
          "payload": {
            "__location": `https://chat.deepseek.com/a/chat/s/${refConvId}`,
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "type": "warmStart",
            "referer": "",
            "metricDuration": fakeDuration2,
            "metricVisitIndex": 0,
            "metricDurationSinceMounted": 0,
            "hasError": "false"
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 1300 + Math.floor(Math.random() * 1000),
          "event_name": "__httpResponse",
          "event_message": `httpResponse POST /api/v0/chat/completion, ${fakeDuration3}ms, reason: none`,
          "payload": {
            "__location": `https://chat.deepseek.com/a/chat/s/${refConvId}`,
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "url": "/api/v0/chat/completion",
            "path": "/api/v0/chat/completion",
            "method": "POST",
            "metricDuration": fakeDuration3,
            "status": "200",
            "logId": util.uuid()
          },
          "level": "info"
        },
        {
          "session_id": sessionId,
          "client_timestamp_ms": timestamp + 1400 + Math.floor(Math.floor(Math.random() * 1000)),
          "event_name": "completionApiOk",
          "event_message": "完成响应，响应有正常的的 finish reason",
          "payload": {
            "__location": `https://chat.deepseek.com/a/chat/s/${refConvId}`,
            "__ip": ipAddress,
            "__region": "CN",
            "__pageVisibility": "true",
            "__nodeEnv": "production",
            "__deployEnv": "production",
            "__appVersion": FAKE_HEADERS["X-App-Version"],
            "__commitId": EVENT_COMMIT_ID,
            "__userAgent": FAKE_HEADERS["User-Agent"],
            "__referrer": "",
            "condition": "hasDone",
            "streamClosed": false,
            "scene": "completion",
            "chatSessionId": refConvId
          },
          "level": "info"
        }
      ]
    }, {
      headers: {
        Authorization: `Bearer ${token}`,
        ...FAKE_HEADERS,
        Referer: `https://chat.deepseek.com/a/chat/s/${refConvId}`,
        Cookie: generateCookie()
      },
      validateStatus: () => true,
    });
    checkResult(response, refreshToken);
    logger.info('发送事件成功');
  }
  catch (err) {
    logger.error(err);
  }
}

/**
 * 获取深度思考配额
 */
async function getThinkingQuota(refreshToken: string) {
  try {
    const response = await axios.get('https://chat.deepseek.com/api/v0/users/feature_quota', {
      headers: {
        Authorization: `Bearer ${refreshToken}`,
        ...FAKE_HEADERS,
        Cookie: generateCookie()
      },
      timeout: 15000,
      validateStatus: () => true,
    });
    const { biz_data } = checkResult(response, refreshToken);
    if (!biz_data) return 0;
    const { quota, used } = biz_data.thinking;
    if (!_.isFinite(quota) || !_.isFinite(used)) return 0;
    logger.info(`获取深度思考配额: ${quota}/${used}`);
    return quota - used;
  }
  catch (err) {
    logger.error('获取深度思考配额失败:', err);
    return 0;
  }
}

/**
 * 获取版本号
 */
async function fetchAppVersion(): Promise<string> {
  try {
    logger.info('自动获取版本号');
    const response = await axios.get('https://chat.deepseek.com/version.txt', {
      timeout: 5000,
      validateStatus: () => true,
      headers: {
        ...FAKE_HEADERS,
        Cookie: generateCookie()
      }
    });
    if (response.status === 200 && response.data) {
      // 移除所有非法字符（换行符、回车符、制表符等）
      const version = response.data.toString().replace(/[\r\n\t\s]+/g, '').trim();
      if (version && /^[\w.-]+$/.test(version)) {
        logger.info(`获取版本号: ${version}`);
        return version;
      }
    }
  } catch (err) {
    logger.error('获取版本号失败:', err);
  }
  return "20241018.0";
}

function autoUpdateAppVersion() {
  fetchAppVersion().then((version) => {
    FAKE_HEADERS["X-App-Version"] = version;
  });
}

util.createCronJob('0 */10 * * * *', autoUpdateAppVersion).start();

getIPAddress().then(() => {
  autoUpdateAppVersion();
}).catch((err) => {
  logger.error('获取 IP 地址失败:', err);
});

export default {
  createCompletion,
  createCompletionStream,
  getTokenLiveStatus,
  tokenSplit,
  fetchAppVersion,
};
