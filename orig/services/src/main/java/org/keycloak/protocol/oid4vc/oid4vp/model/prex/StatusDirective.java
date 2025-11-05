/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.oid4vp.model.prex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

import javax.annotation.processing.Generated;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "directive",
        "type"
})
@Generated("jsonschema2pojo")
public class StatusDirective {

    @JsonProperty("directive")
    private Directive directive;
    @JsonProperty("type")
    private List<String> type = new ArrayList<String>();

    @JsonProperty("directive")
    public Directive getDirective() {
        return directive;
    }

    @JsonProperty("directive")
    public void setDirective(Directive directive) {
        this.directive = directive;
    }

    @JsonProperty("type")
    public List<String> getType() {
        return type;
    }

    @JsonProperty("type")
    public void setType(List<String> type) {
        this.type = type;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(StatusDirective.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("directive");
        sb.append('=');
        sb.append(((this.directive == null) ? "<null>" : this.directive));
        sb.append(',');
        sb.append("type");
        sb.append('=');
        sb.append(((this.type == null) ? "<null>" : this.type));
        sb.append(',');
        if (sb.charAt((sb.length() - 1)) == ',') {
            sb.setCharAt((sb.length() - 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result * 31) + ((this.type == null) ? 0 : this.type.hashCode()));
        result = ((result * 31) + ((this.directive == null) ? 0 : this.directive.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof StatusDirective) == false) {
            return false;
        }
        StatusDirective rhs = ((StatusDirective) other);
        return (((this.type == rhs.type) || ((this.type != null) && this.type.equals(rhs.type))) && ((this.directive == rhs.directive) || ((this.directive != null) && this.directive.equals(rhs.directive))));
    }

    @Generated("jsonschema2pojo")
    public enum Directive {

        REQUIRED("required"),
        ALLOWED("allowed"),
        DISALLOWED("disallowed");
        private final static Map<String, Directive> CONSTANTS = new HashMap<String, Directive>();

        static {
            for (Directive c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        Directive(String value) {
            this.value = value;
        }

        @JsonCreator
        public static Directive fromValue(String value) {
            Directive constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

    }

}
