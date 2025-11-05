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


/**
 * Presentation Submission
 * <p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "id",
        "definition_id",
        "descriptor_map"
})
@Generated("jsonschema2pojo")
public class PresentationSubmission {

    /**
     * (Required)
     */
    @JsonProperty("id")
    private String id;
    /**
     * (Required)
     */
    @JsonProperty("definition_id")
    private String definitionId;
    /**
     * (Required)
     */
    @JsonProperty("descriptor_map")
    private List<Descriptor> descriptorMap = new ArrayList<Descriptor>();

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
    @JsonProperty("definition_id")
    public String getDefinitionId() {
        return definitionId;
    }

    /**
     * (Required)
     */
    @JsonProperty("definition_id")
    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
    }

    /**
     * (Required)
     */
    @JsonProperty("descriptor_map")
    public List<Descriptor> getDescriptorMap() {
        return descriptorMap;
    }

    /**
     * (Required)
     */
    @JsonProperty("descriptor_map")
    public void setDescriptorMap(List<Descriptor> descriptorMap) {
        this.descriptorMap = descriptorMap;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(PresentationSubmission.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("id");
        sb.append('=');
        sb.append(((this.id == null) ? "<null>" : this.id));
        sb.append(',');
        sb.append("definitionId");
        sb.append('=');
        sb.append(((this.definitionId == null) ? "<null>" : this.definitionId));
        sb.append(',');
        sb.append("descriptorMap");
        sb.append('=');
        sb.append(((this.descriptorMap == null) ? "<null>" : this.descriptorMap));
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
        result = ((result * 31) + ((this.id == null) ? 0 : this.id.hashCode()));
        result = ((result * 31) + ((this.descriptorMap == null) ? 0 : this.descriptorMap.hashCode()));
        result = ((result * 31) + ((this.definitionId == null) ? 0 : this.definitionId.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof PresentationSubmission) == false) {
            return false;
        }
        PresentationSubmission rhs = ((PresentationSubmission) other);
        return ((((this.id == rhs.id) || ((this.id != null) && this.id.equals(rhs.id))) && ((this.descriptorMap == rhs.descriptorMap) || ((this.descriptorMap != null) && this.descriptorMap.equals(rhs.descriptorMap)))) && ((this.definitionId == rhs.definitionId) || ((this.definitionId != null) && this.definitionId.equals(rhs.definitionId))));
    }

}
