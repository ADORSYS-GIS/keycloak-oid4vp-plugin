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
 * Presentation Definition
 * <p>
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder({
        "id",
        "name",
        "purpose",
        "format",
        "frame",
        "submission_requirements",
        "input_descriptors"
})
@Generated("jsonschema2pojo")
public class PresentationDefinition {

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
    @JsonProperty("frame")
    private Frame frame;
    @JsonProperty("submission_requirements")
    private List<SubmissionRequirement> submissionRequirements = new ArrayList<SubmissionRequirement>();
    /**
     * (Required)
     */
    @JsonProperty("input_descriptors")
    private List<InputDescriptor> inputDescriptors = new ArrayList<InputDescriptor>();

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

    @JsonProperty("frame")
    public Frame getFrame() {
        return frame;
    }

    @JsonProperty("frame")
    public void setFrame(Frame frame) {
        this.frame = frame;
    }

    @JsonProperty("submission_requirements")
    public List<SubmissionRequirement> getSubmissionRequirements() {
        return submissionRequirements;
    }

    @JsonProperty("submission_requirements")
    public void setSubmissionRequirements(List<SubmissionRequirement> submissionRequirements) {
        this.submissionRequirements = submissionRequirements;
    }

    /**
     * (Required)
     */
    @JsonProperty("input_descriptors")
    public List<InputDescriptor> getInputDescriptors() {
        return inputDescriptors;
    }

    /**
     * (Required)
     */
    @JsonProperty("input_descriptors")
    public void setInputDescriptors(List<InputDescriptor> inputDescriptors) {
        this.inputDescriptors = inputDescriptors;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(PresentationDefinition.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
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
        sb.append("frame");
        sb.append('=');
        sb.append(((this.frame == null) ? "<null>" : this.frame));
        sb.append(',');
        sb.append("submissionRequirements");
        sb.append('=');
        sb.append(((this.submissionRequirements == null) ? "<null>" : this.submissionRequirements));
        sb.append(',');
        sb.append("inputDescriptors");
        sb.append('=');
        sb.append(((this.inputDescriptors == null) ? "<null>" : this.inputDescriptors));
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
        result = ((result * 31) + ((this.submissionRequirements == null) ? 0 : this.submissionRequirements.hashCode()));
        result = ((result * 31) + ((this.name == null) ? 0 : this.name.hashCode()));
        result = ((result * 31) + ((this.format == null) ? 0 : this.format.hashCode()));
        result = ((result * 31) + ((this.id == null) ? 0 : this.id.hashCode()));
        result = ((result * 31) + ((this.inputDescriptors == null) ? 0 : this.inputDescriptors.hashCode()));
        result = ((result * 31) + ((this.frame == null) ? 0 : this.frame.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof PresentationDefinition) == false) {
            return false;
        }
        PresentationDefinition rhs = ((PresentationDefinition) other);
        return ((((((((this.purpose == rhs.purpose) || ((this.purpose != null) && this.purpose.equals(rhs.purpose))) && ((this.submissionRequirements == rhs.submissionRequirements) || ((this.submissionRequirements != null) && this.submissionRequirements.equals(rhs.submissionRequirements)))) && ((this.name == rhs.name) || ((this.name != null) && this.name.equals(rhs.name)))) && ((this.format == rhs.format) || ((this.format != null) && this.format.equals(rhs.format)))) && ((this.id == rhs.id) || ((this.id != null) && this.id.equals(rhs.id)))) && ((this.inputDescriptors == rhs.inputDescriptors) || ((this.inputDescriptors != null) && this.inputDescriptors.equals(rhs.inputDescriptors)))) && ((this.frame == rhs.frame) || ((this.frame != null) && this.frame.equals(rhs.frame))));
    }

}
