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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import javax.annotation.processing.Generated;
import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder({
        "sd-jwt_alg_values",
        "kb-jwt_alg_values"
})
@Generated("jsonschema2pojo")
public class SdGenericFormat {

    @JsonProperty("sd-jwt_alg_values")
    private List<String> sdJwtAlgValues = new ArrayList<String>();
    @JsonProperty("kb-jwt_alg_values")
    private List<String> kbJwtAlgValues = new ArrayList<String>();

    @JsonProperty("sd-jwt_alg_values")
    public List<String> getSdJwtAlgValues() {
        return sdJwtAlgValues;
    }

    @JsonProperty("sd-jwt_alg_values")
    public void setSdJwtAlgValues(List<String> sdJwtAlgValues) {
        this.sdJwtAlgValues = sdJwtAlgValues;
    }

    @JsonProperty("kb-jwt_alg_values")
    public List<String> getKbJwtAlgValues() {
        return kbJwtAlgValues;
    }

    @JsonProperty("kb-jwt_alg_values")
    public void setKbJwtAlgValues(List<String> kbJwtAlgValues) {
        this.kbJwtAlgValues = kbJwtAlgValues;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(SdGenericFormat.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("sdJwtAlgValues");
        sb.append('=');
        sb.append(((this.sdJwtAlgValues == null) ? "<null>" : this.sdJwtAlgValues));
        sb.append(',');
        sb.append("kbJwtAlgValues");
        sb.append('=');
        sb.append(((this.kbJwtAlgValues == null) ? "<null>" : this.kbJwtAlgValues));
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
        result = ((result * 31) + ((this.kbJwtAlgValues == null) ? 0 : this.kbJwtAlgValues.hashCode()));
        result = ((result * 31) + ((this.sdJwtAlgValues == null) ? 0 : this.sdJwtAlgValues.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof SdGenericFormat) == false) {
            return false;
        }
        SdGenericFormat rhs = ((SdGenericFormat) other);
        return (((this.kbJwtAlgValues == rhs.kbJwtAlgValues) || ((this.kbJwtAlgValues != null) && this.kbJwtAlgValues.equals(rhs.kbJwtAlgValues))) && ((this.sdJwtAlgValues == rhs.sdJwtAlgValues) || ((this.sdJwtAlgValues != null) && this.sdJwtAlgValues.equals(rhs.sdJwtAlgValues))));
    }

}
