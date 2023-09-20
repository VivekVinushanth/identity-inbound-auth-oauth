/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.choreo.callback;

import com.google.gson.Gson;
import jdk.nashorn.api.scripting.JSObject;
import jdk.nashorn.api.scripting.ScriptObjectMirror;

import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;

import java.util.Map;

import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

public class CallbackImpl implements Callback {

    JSEngine jsBasedEngine;

    private CallbackImpl(JSEngine jsBasedEngine) {
        this.jsBasedEngine = jsBasedEngine;
    }
    private static Callback CALLBACK_INSTANCE = null;

    /**
     * Returns an instance to log the javascript errors.
     *
     * @return jsBasedEngineInstance instance.
     */
    public static Callback getInstance(JSEngine jsBasedEngine) {

        if (CALLBACK_INSTANCE == null) {
            CALLBACK_INSTANCE = new CallbackImpl(jsBasedEngine);
        }
        return CALLBACK_INSTANCE;
    }


    @Override
    public void accept(Map<String, Object> eventHandlers, Map<String, Object> data, String outCome) {

        try {
            String source = eventHandlers.get(outCome).toString();
            Gson gson = new Gson();
            String json = gson.toJson(data);
            ScriptObjectMirror obj = (ScriptObjectMirror) jsBasedEngine.getEngine().eval ("(" + json + ")");
            apply(jsBasedEngine.getEngine(), source, obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Object apply(ScriptEngine scriptEngine, String source, Object... params) {

        Compilable compilable = (Compilable) scriptEngine;
        try {
            CompiledScript compiledScript = compilable.compile(source);
            JSObject jsObject = (JSObject) compiledScript.eval();
            if (jsObject instanceof ScriptObjectMirror) {
                ScriptObjectMirror scriptObjectMirror = (ScriptObjectMirror) jsObject;
                if (!scriptObjectMirror.isFunction()) {
                    return scriptObjectMirror;
                }
                return scriptObjectMirror.call(null, params);
            }
        } catch (ScriptException e) {

        }
        return null;
    }
}