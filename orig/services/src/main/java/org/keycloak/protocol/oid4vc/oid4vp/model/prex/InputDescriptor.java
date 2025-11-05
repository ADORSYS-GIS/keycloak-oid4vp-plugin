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
        "name",
        "purpose",
        "format",
        "group",
        "constraints"
})
@Generated("jsonschema2pojo")
public class InputDescriptor {

    /**
     * (Required)
     */
    @JsonProperty("id")
    private String id;
    @JsonProperty("name")
    private String name;
    @JsonProperty("purpose")
    private String purpose;
    /**
     * Presentation Definition Claim Format Designations
     * <p>
     */
    @JsonProperty("format")
    private ClaimFormat format;
    @JsonProperty("group")
    private List<String> group = new ArrayList<String>();
    /**
     * (Required)
     */
    @JsonProperty("constraints")
    private Constraints constraints;

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

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("purpose")
    public String getPurpose() {
        return purpose;
    }

    @JsonProperty("purpose")
    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    /**
     * Presentation Definition Claim Format Designations
     * <p>
     */
    @JsonProperty("format")
    public ClaimFormat getFormat() {
        return format;
    }

    /**
     * Presentation Definition Claim Format Designations
     * <p>
     */
    @JsonProperty("format")
    public void setFormat(ClaimFormat format) {
        this.format = format;
    }

    @JsonProperty("group")
    public List<String> getGroup() {
        return group;
    }

    @JsonProperty("group")
    public void setGroup(List<String> group) {
        this.group = group;
    }

    /**
     * (Required)
     */
    @JsonProperty("constraints")
    public Constraints getConstraints() {
        return constraints;
    }

    /**
     * (Required)
     */
    @JsonProperty("constraints")
    public void setConstraints(Constraints constraints) {
        this.constraints = constraints;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(InputDescriptor.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("id");
        sb.append('=');
        sb.append(((this.id == null) ? "<null>" : this.id));
        sb.append(',');
        sb.append("name");
        sb.append('=');
        sb.append(((this.name == null) ? "<null>" : this.name));
        sb.append(',');
        sb.append("purpose");
        sb.append('=');
        sb.append(((this.purpose == null) ? "<null>" : this.purpose));
        sb.append(',');
        sb.append("format");
        sb.append('=');
        sb.append(((this.format == null) ? "<null>" : this.format));
        sb.append(',');
        sb.append("group");
        sb.append('=');
        sb.append(((this.group == null) ? "<null>" : this.group));
        sb.append(',');
        sb.append("constraints");
        sb.append('=');
        sb.append(((this.constraints == null) ? "<null>" : this.constraints));
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
        result = ((result * 31) + ((this.purpose == null) ? 0 : this.purpose.hashCode()));
        result = ((result * 31) + ((this.name == null) ? 0 : this.name.hashCode()));
        result = ((result * 31) + ((this.format == null) ? 0 : this.format.hashCode()));
        result = ((result * 31) + ((this.id == null) ? 0 : this.id.hashCode()));
        result = ((result * 31) + ((this.constraints == null) ? 0 : this.constraints.hashCode()));
        result = ((result * 31) + ((this.group == null) ? 0 : this.group.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof InputDescriptor) == false) {
            return false;
        }
        InputDescriptor rhs = ((InputDescriptor) other);
        return (((((((this.purpose == rhs.purpose) || ((this.purpose != null) && this.purpose.equals(rhs.purpose))) && ((this.name == rhs.name) || ((this.name != null) && this.name.equals(rhs.name)))) && ((this.format == rhs.format) || ((this.format != null) && this.format.equals(rhs.format)))) && ((this.id == rhs.id) || ((this.id != null) && this.id.equals(rhs.id)))) && ((this.constraints == rhs.constraints) || ((this.constraints != null) && this.constraints.equals(rhs.constraints)))) && ((this.group == rhs.group) || ((this.group != null) && this.group.equals(rhs.group))));
    }

}
