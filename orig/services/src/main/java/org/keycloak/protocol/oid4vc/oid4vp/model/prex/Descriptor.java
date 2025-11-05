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
import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "id",
        "path",
        "path_nested",
        "format"
})
@Generated("jsonschema2pojo")
public class Descriptor {

    /**
     * (Required)
     */
    @JsonProperty("id")
    private String id;
    /**
     * (Required)
     */
    @JsonProperty("path")
    private String path;
    @JsonProperty("path_nested")
    private Descriptor pathNested;
    /**
     * (Required)
     */
    @JsonProperty("format")
    private Format format;

    /**
     * (Required)
     */
    @JsonProperty("id")
    public String getId() {
        return id;
    }

    /**
     * (Required)
     */
    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    /**
     * (Required)
     */
    @JsonProperty("path")
    public String getPath() {
        return path;
    }

    /**
     * (Required)
     */
    @JsonProperty("path")
    public void setPath(String path) {
        this.path = path;
    }

    @JsonProperty("path_nested")
    public Descriptor getPathNested() {
        return pathNested;
    }

    @JsonProperty("path_nested")
    public void setPathNested(Descriptor pathNested) {
        this.pathNested = pathNested;
    }

    /**
     * (Required)
     */
    @JsonProperty("format")
    public Format getFormat() {
        return format;
    }

    /**
     * (Required)
     */
    @JsonProperty("format")
    public void setFormat(Format format) {
        this.format = format;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Descriptor.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("id");
        sb.append('=');
        sb.append(((this.id == null) ? "<null>" : this.id));
        sb.append(',');
        sb.append("path");
        sb.append('=');
        sb.append(((this.path == null) ? "<null>" : this.path));
        sb.append(',');
        sb.append("pathNested");
        sb.append('=');
        sb.append(((this.pathNested == null) ? "<null>" : this.pathNested));
        sb.append(',');
        sb.append("format");
        sb.append('=');
        sb.append(((this.format == null) ? "<null>" : this.format));
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
        result = ((result * 31) + ((this.format == null) ? 0 : this.format.hashCode()));
        result = ((result * 31) + ((this.path == null) ? 0 : this.path.hashCode()));
        result = ((result * 31) + ((this.id == null) ? 0 : this.id.hashCode()));
        result = ((result * 31) + ((this.pathNested == null) ? 0 : this.pathNested.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Descriptor) == false) {
            return false;
        }
        Descriptor rhs = ((Descriptor) other);
        return (((((this.format == rhs.format) || ((this.format != null) && this.format.equals(rhs.format))) && ((this.path == rhs.path) || ((this.path != null) && this.path.equals(rhs.path)))) && ((this.id == rhs.id) || ((this.id != null) && this.id.equals(rhs.id)))) && ((this.pathNested == rhs.pathNested) || ((this.pathNested != null) && this.pathNested.equals(rhs.pathNested))));
    }

    @Generated("jsonschema2pojo")
    public enum Format {

        JWT("jwt"),
        JWT_VC("jwt_vc"),
        JWT_VP("jwt_vp"),
        LDP("ldp"),
        LDP_VC("ldp_vc"),
        LDP_VP("ldp_vp"),
        VC_SD_JWT("vc+sd-jwt"),
        DC_SD_JWT("dc+sd-jwt");
        private final static Map<String, Format> CONSTANTS = new HashMap<String, Format>();

        static {
            for (Format c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        Format(String value) {
            this.value = value;
        }

        @JsonCreator
        public static Format fromValue(String value) {
            Format constant = CONSTANTS.get(value);
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
