# 工具调用（Tool Calling）使用示例

## 概述

现在 completions 接口已支持工具调用功能，允许模型在需要时调用外部工具/函数。

## 请求格式

### 基本请求结构

```json
{
  "model": "deepseek-chat",
  "messages": [
    {
      "role": "user",
      "content": "北京今天天气怎么样？"
    }
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "获取指定城市的天气信息",
        "parameters": {
          "type": "object",
          "properties": {
            "city": {
              "type": "string",
              "description": "城市名称，例如：北京、上海"
            },
            "unit": {
              "type": "string",
              "enum": ["celsius", "fahrenheit"],
              "description": "温度单位"
            }
          },
          "required": ["city"]
        }
      }
    }
  ],
  "tool_choice": "auto",
  "stream": false
}
```

### 参数说明

- `tools`: 工具列表，每个工具包含：
  - `type`: 固定为 "function"
  - `function`: 函数定义
    - `name`: 函数名称
    - `description`: 函数描述（可选）
    - `parameters`: JSON Schema 格式的参数定义

- `tool_choice`: 工具选择策略
  - `"auto"`: 自动决定是否调用工具（默认）
  - `"none"`: 不调用工具
  - `{"type": "function", "function": {"name": "函数名"}}`: 强制调用指定函数

## 响应格式

### 非流式响应

当模型决定调用工具时：

```json
{
  "id": "session-id@message-id",
  "model": "deepseek-chat",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "",
        "tool_calls": [
          {
            "id": "call_abc123",
            "type": "function",
            "function": {
              "name": "get_weather",
              "arguments": "{\"city\":\"北京\",\"unit\":\"celsius\"}"
            }
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ],
  "usage": {
    "prompt_tokens": 1,
    "completion_tokens": 1,
    "total_tokens": 2
  },
  "created": 1234567890
}
```

### 流式响应

流式响应会逐步发送工具调用信息：

```
data: {"id":"session-id@message-id","model":"deepseek-chat","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}],"created":1234567890}

data: {"id":"session-id@message-id","model":"deepseek-chat","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_abc123","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}],"created":1234567890}

data: {"id":"session-id@message-id","model":"deepseek-chat","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\""}}]},"finish_reason":null}],"created":1234567890}

data: {"id":"session-id@message-id","model":"deepseek-chat","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\"北京\""}}]},"finish_reason":null}],"created":1234567890}

data: {"id":"session-id@message-id","model":"deepseek-chat","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"}"}}]},"finish_reason":null}],"created":1234567890}

data: {"id":"session-id@message-id","model":"deepseek-chat","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":"tool_calls"}],"created":1234567890}

data: [DONE]
```

## 完整工作流程

1. **发送带工具定义的请求**
2. **模型返回工具调用** (finish_reason = "tool_calls")
3. **执行工具并获取结果**
4. **将工具结果添加到对话历史**
5. **再次发送请求获取最终答案**

### 示例：完整对话流程

```javascript
// 第一次请求
const request1 = {
  model: "deepseek-chat",
  messages: [
    { role: "user", content: "北京今天天气怎么样？" }
  ],
  tools: [
    {
      type: "function",
      function: {
        name: "get_weather",
        description: "获取指定城市的天气信息",
        parameters: {
          type: "object",
          properties: {
            city: { type: "string", description: "城市名称" }
          },
          required: ["city"]
        }
      }
    }
  ]
};

// 第一次响应（模型决定调用工具）
const response1 = {
  choices: [{
    message: {
      role: "assistant",
      tool_calls: [{
        id: "call_abc123",
        type: "function",
        function: {
          name: "get_weather",
          arguments: '{"city":"北京"}'
        }
      }]
    },
    finish_reason: "tool_calls"
  }]
};

// 执行工具
const weatherResult = getWeather("北京"); // 假设返回 "晴天，25°C"

// 第二次请求（包含工具调用结果）
const request2 = {
  model: "deepseek-chat",
  messages: [
    { role: "user", content: "北京今天天气怎么样？" },
    {
      role: "assistant",
      tool_calls: [{
        id: "call_abc123",
        type: "function",
        function: {
          name: "get_weather",
          arguments: '{"city":"北京"}'
        }
      }]
    },
    {
      role: "tool",
      tool_call_id: "call_abc123",
      content: "晴天，25°C"
    }
  ],
  tools: [/* 同上 */]
};

// 第二次响应（最终答案）
const response2 = {
  choices: [{
    message: {
      role: "assistant",
      content: "北京今天天气晴朗，温度为25摄氏度。"
    },
    finish_reason: "stop"
  }]
};
```

## 注意事项

1. 工具调用功能与 DeepSeek API 的原生工具调用接口兼容
2. 支持同时定义多个工具，模型会根据需要选择合适的工具
3. 工具调用可以与流式响应结合使用
4. 确保工具的 `parameters` 遵循 JSON Schema 规范
5. 工具执行逻辑需要在客户端实现

## cURL 示例

```bash
curl -X POST http://localhost:5000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "model": "deepseek-chat",
    "messages": [
      {
        "role": "user",
        "content": "北京今天天气怎么样？"
      }
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "get_weather",
          "description": "获取指定城市的天气信息",
          "parameters": {
            "type": "object",
            "properties": {
              "city": {
                "type": "string",
                "description": "城市名称"
              }
            },
            "required": ["city"]
          }
        }
      }
    ],
    "tool_choice": "auto",
    "stream": false
  }'
```
