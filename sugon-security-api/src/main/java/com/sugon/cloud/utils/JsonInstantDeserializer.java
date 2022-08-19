package com.sugon.cloud.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

/**
 * @Author: yangdingshan
 * @Date: 2022/1/19 15:37
 * @Description: 对Instant类型日期的反序列化
 */
public class JsonInstantDeserializer extends JsonDeserializer<Instant> {

    @Override
    public Instant deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        long date;
        try {
            date = jsonParser.getLongValue();
        } catch (Exception e) {
            if (Objects.equals(jsonParser.getValueAsString(), "null")) {
                return null;
            }
            long longValue = Long.parseLong(jsonParser.getValueAsString());
            return Instant.ofEpochMilli(longValue);
        }
        return Instant.ofEpochMilli(date);
    }
}
