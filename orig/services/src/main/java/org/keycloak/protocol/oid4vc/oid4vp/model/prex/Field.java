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
        "id",
        "optional",
        "path",
        "purpose",
        "name",
        "intent_to_retain",
        "filter"
})
@Generated("jsonschema2pojo")
public class Field {

    @JsonProperty("id")
    private String id;
    @JsonProperty("optional")
    private Boolean optional;
    /**
     * (Required)
     */
    @JsonProperty("path")
    private List<String> path = new ArrayList<String>();
    @JsonProperty("purpose")
    private String purpose;
    @JsonProperty("name")
    private String name;
    @JsonProperty("intent_to_retain")
    private Boolean intentToRetain;
    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("filter")
    private Filter filter = null;

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("optional")
    public Boolean getOptional() {
        return optional;
    }

    @JsonProperty("optional")
    public void setOptional(Boolean optional) {
        this.optional = optional;
    }

    /**
     * (Required)
     */
    @JsonProperty("path")
    public List<String> getPath() {
        return path;
    }

    /**
     * (Required)
     */
    @JsonProperty("path")
    public void setPath(List<String> path) {
        this.path = path;
    }

    @JsonProperty("purpose")
    public String getPurpose() {
        return purpose;
    }

    @JsonProperty("purpose")
    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("intent_to_retain")
    public Boolean getIntentToRetain() {
        return intentToRetain;
    }

    @JsonProperty("intent_to_retain")
    public void setIntentToRetain(Boolean intentToRetain) {
        this.intentToRetain = intentToRetain;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("filter")
    public Filter getFilter() {
        return filter;
    }

    /**
     * Core schema meta-schema
     * <p>
     */
    @JsonProperty("filter")
    public void setFilter(Filter filter) {
        this.filter = filter;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Field.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("id");
        sb.append('=');
        sb.append(((this.id == null) ? "<null>" : this.id));
        sb.append(',');
        sb.append("optional");
        sb.append('=');
        sb.append(((this.optional == null) ? "<null>" : this.optional));
        sb.append(',');
        sb.append("path");
        sb.append('=');
        sb.append(((this.path == null) ? "<null>" : this.path));
        sb.append(',');
        sb.append("purpose");
        sb.append('=');
        sb.append(((this.purpose == null) ? "<null>" : this.purpose));
        sb.append(',');
        sb.append("name");
        sb.append('=');
        sb.append(((this.name == null) ? "<null>" : this.name));
        sb.append(',');
        sb.append("intentToRetain");
        sb.append('=');
        sb.append(((this.intentToRetain == null) ? "<null>" : this.intentToRetain));
        sb.append(',');
        sb.append("filter");
        sb.append('=');
        sb.append(((this.filter == null) ? "<null>" : this.filter));
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
        result = ((result * 31) + ((this.filter == null) ? 0 : this.filter.hashCode()));
        result = ((result * 31) + ((this.path == null) ? 0 : this.path.hashCode()));
        result = ((result * 31) + ((this.intentToRetain == null) ? 0 : this.intentToRetain.hashCode()));
        result = ((result * 31) + ((this.purpose == null) ? 0 : this.purpose.hashCode()));
        result = ((result * 31) + ((this.name == null) ? 0 : this.name.hashCode()));
        result = ((result * 31) + ((this.optional == null) ? 0 : this.optional.hashCode()));
        result = ((result * 31) + ((this.id == null) ? 0 : this.id.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Field) == false) {
            return false;
        }
        Field rhs = ((Field) other);
        return ((((((((this.filter == rhs.filter) || ((this.filter != null) && this.filter.equals(rhs.filter))) && ((this.path == rhs.path) || ((this.path != null) && this.path.equals(rhs.path)))) && ((this.intentToRetain == rhs.intentToRetain) || ((this.intentToRetain != null) && this.intentToRetain.equals(rhs.intentToRetain)))) && ((this.purpose == rhs.purpose) || ((this.purpose != null) && this.purpose.equals(rhs.purpose)))) && ((this.name == rhs.name) || ((this.name != null) && this.name.equals(rhs.name)))) && ((this.optional == rhs.optional) || ((this.optional != null) && this.optional.equals(rhs.optional)))) && ((this.id == rhs.id) || ((this.id != null) && this.id.equals(rhs.id))));
    }

}
