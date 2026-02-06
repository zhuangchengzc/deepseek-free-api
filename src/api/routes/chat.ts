import _ from 'lodash';

import Request from '@/lib/request/Request.ts';
import Response from '@/lib/response/Response.ts';
import chat from '@/api/controllers/chat.ts';
import APIException from '@/lib/exceptions/APIException.ts';
import EX from '@/api/consts/exceptions.ts';
import process from "process";


const DEEP_SEEK_CHAT_AUTHORIZATION = process.env.DEEP_SEEK_CHAT_AUTHORIZATION;

export default {

    prefix: '/v1/chat',

    post: {

        '/completions': async (request: Request) => {
            // 如果环境变量有 token，先覆盖请求头再进行校验
            if (DEEP_SEEK_CHAT_AUTHORIZATION) {
                request.headers.authorization = "Bearer " + DEEP_SEEK_CHAT_AUTHORIZATION;
            }
            request
                .validate('body.conversation_id', v => _.isUndefined(v) || _.isString(v))
                .validate('body.messages', _.isArray)
                .validate('body.tools', v => _.isUndefined(v) || _.isArray(v))
                .validate('body.tool_choice', v => _.isUndefined(v) || _.isString(v) || _.isObject(v))
                .validate('headers.authorization', v => _.isUndefined(v) || _.isString(v) || _.isArray(v))
            // token切分前确保 header 不为空
            let authHeader = request.headers.authorization;
            if (Array.isArray(authHeader)) authHeader = authHeader.join(',');
            const tokens = chat.tokenSplit(authHeader);
            if (!tokens || tokens.length === 0) {
                throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'Params headers.authorization invalid');
            }
            // 随机挑选一个token
            const token = _.sample(tokens);
            let { model, conversation_id: convId, messages, stream, tools, tool_choice: toolChoice } = request.body;
            model = model.toLowerCase();
            if (stream) {
                const stream = await chat.createCompletionStream(model, messages, token, convId, 0, tools, toolChoice);
                return new Response(stream, {
                    type: "text/event-stream"
                });
            }
            else {
                const result = await chat.createCompletion(model, messages, token, convId, 0, tools, toolChoice);
                return result;
            }
        }

    }

}
