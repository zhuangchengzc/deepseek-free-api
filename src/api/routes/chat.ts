import _ from 'lodash';

import Request from '@/lib/request/Request.ts';
import Response from '@/lib/response/Response.ts';
import chat from '@/api/controllers/chat.ts';
import APIException from '@/lib/exceptions/APIException.ts';
import EX from '@/api/consts/exceptions.ts';
import logger from '@/lib/logger.ts';
import process from "process";


const DEEP_SEEK_CHAT_AUTHORIZATION = process.env.DEEP_SEEK_CHAT_AUTHORIZATION;
logger.info('[ENV] DEEP_SEEK_CHAT_AUTHORIZATION:', DEEP_SEEK_CHAT_AUTHORIZATION);

export default {

    prefix: '/v1/chat',

    post: {

        '/completions': async (request: Request) => {
            // 如果环境变量有 token，先覆盖请求头再进行校验
            logger.info('[DEBUG] 环境变量 DEEP_SEEK_CHAT_AUTHORIZATION:', DEEP_SEEK_CHAT_AUTHORIZATION);
            logger.info('[DEBUG] 请求头 authorization:', request.headers.authorization);
            if (DEEP_SEEK_CHAT_AUTHORIZATION) {
                request.headers.authorization = "Bearer " + DEEP_SEEK_CHAT_AUTHORIZATION;
                logger.info('[DEBUG] 使用环境变量覆盖请求头');
            }
            request
                .validate('body.conversation_id', v => _.isUndefined(v) || _.isString(v))
                .validate('body.messages', _.isArray)
                .validate('headers.authorization', v => _.isUndefined(v) || _.isString(v) || _.isArray(v))
            // token切分前确保 header 不为空
            let authHeader = request.headers.authorization;
            if (Array.isArray(authHeader)) authHeader = authHeader.join(',');
            logger.info('[DEBUG] authHeader:', authHeader);
            const tokens = chat.tokenSplit(authHeader);
            logger.info('[DEBUG] 切分后的 tokens 数量:', tokens.length);
            if (!tokens || tokens.length === 0) {
                throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'Params headers.authorization invalid');
            }
            // 随机挑选一个token
            const token = _.sample(tokens);
            logger.info('[DEBUG] 选中的 token (前20字符):', token ? token.substring(0, 20) + '...' : 'null');
            let { model, conversation_id: convId, messages, stream } = request.body;
            logger.info('[DEBUG] stream 参数:', stream);
            model = model.toLowerCase();
            if (stream) {
                logger.info('[DEBUG] 使用流式响应');
                const stream = await chat.createCompletionStream(model, messages, token, convId);
                return new Response(stream, {
                    type: "text/event-stream"
                });
            }
            else {
                logger.info('[DEBUG] 使用非流式响应');
                const result = await chat.createCompletion(model, messages, token, convId);
                logger.info('[DEBUG] 非流式响应结果:', JSON.stringify(result).substring(0, 200));
                return result;
            }
        }

    }

}
