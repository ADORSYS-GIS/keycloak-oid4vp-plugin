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

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder({"limit_disclosure", "statuses", "fields", "subject_is_issuer", "is_holder", "same_subject"})
@Generated("jsonschema2pojo")
public class Constraints {

    @JsonProperty("limit_disclosure")
    private LimitDisclosure limitDisclosure;
    @JsonProperty("statuses")
    private Statuses statuses;
    @JsonProperty("fields")
    private List<Field> fields = new ArrayList<Field>();
    @JsonProperty("subject_is_issuer")
    private SubjectIsIssuer subjectIsIssuer;
    @JsonProperty("is_holder")
    private List<IsHolder> isHolder = new ArrayList<IsHolder>();
    @JsonProperty("same_subject")
    private List<SameSubject> sameSubject = new ArrayList<SameSubject>();

    @JsonProperty("limit_disclosure")
    public LimitDisclosure getLimitDisclosure() {
        return limitDisclosure;
    }

    @JsonProperty("limit_disclosure")
    public void setLimitDisclosure(LimitDisclosure limitDisclosure) {
        this.limitDisclosure = limitDisclosure;
    }

    @JsonProperty("statuses")
    public Statuses getStatuses() {
        return statuses;
    }

    @JsonProperty("statuses")
    public void setStatuses(Statuses statuses) {
        this.statuses = statuses;
    }

    @JsonProperty("fields")
    public List<Field> getFields() {
        return fields;
    }

    @JsonProperty("fields")
    public void setFields(List<Field> fields) {
        this.fields = fields;
    }

    @JsonProperty("subject_is_issuer")
    public SubjectIsIssuer getSubjectIsIssuer() {
        return subjectIsIssuer;
    }

    @JsonProperty("subject_is_issuer")
    public void setSubjectIsIssuer(SubjectIsIssuer subjectIsIssuer) {
        this.subjectIsIssuer = subjectIsIssuer;
    }

    @JsonProperty("is_holder")
    public List<IsHolder> getIsHolder() {
        return isHolder;
    }

    @JsonProperty("is_holder")
    public void setIsHolder(List<IsHolder> isHolder) {
        this.isHolder = isHolder;
    }

    @JsonProperty("same_subject")
    public List<SameSubject> getSameSubject() {
        return sameSubject;
    }

    @JsonProperty("same_subject")
    public void setSameSubject(List<SameSubject> sameSubject) {
        this.sameSubject = sameSubject;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Constraints.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("limitDisclosure");
        sb.append('=');
        sb.append(((this.limitDisclosure == null) ? "<null>" : this.limitDisclosure));
        sb.append(',');
        sb.append("statuses");
        sb.append('=');
        sb.append(((this.statuses == null) ? "<null>" : this.statuses));
        sb.append(',');
        sb.append("fields");
        sb.append('=');
        sb.append(((this.fields == null) ? "<null>" : this.fields));
        sb.append(',');
        sb.append("subjectIsIssuer");
        sb.append('=');
        sb.append(((this.subjectIsIssuer == null) ? "<null>" : this.subjectIsIssuer));
        sb.append(',');
        sb.append("isHolder");
        sb.append('=');
        sb.append(((this.isHolder == null) ? "<null>" : this.isHolder));
        sb.append(',');
        sb.append("sameSubject");
        sb.append('=');
        sb.append(((this.sameSubject == null) ? "<null>" : this.sameSubject));
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
        result = ((result * 31) + ((this.isHolder == null) ? 0 : this.isHolder.hashCode()));
        result = ((result * 31) + ((this.subjectIsIssuer == null) ? 0 : this.subjectIsIssuer.hashCode()));
        result = ((result * 31) + ((this.limitDisclosure == null) ? 0 : this.limitDisclosure.hashCode()));
        result = ((result * 31) + ((this.statuses == null) ? 0 : this.statuses.hashCode()));
        result = ((result * 31) + ((this.sameSubject == null) ? 0 : this.sameSubject.hashCode()));
        result = ((result * 31) + ((this.fields == null) ? 0 : this.fields.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Constraints) == false) {
            return false;
        }
        Constraints rhs = ((Constraints) other);
        return (((((((this.isHolder == rhs.isHolder) || ((this.isHolder != null) && this.isHolder.equals(rhs.isHolder))) && ((this.subjectIsIssuer == rhs.subjectIsIssuer) || ((this.subjectIsIssuer != null) && this.subjectIsIssuer.equals(rhs.subjectIsIssuer)))) && ((this.limitDisclosure == rhs.limitDisclosure) || ((this.limitDisclosure != null) && this.limitDisclosure.equals(rhs.limitDisclosure)))) && ((this.statuses == rhs.statuses) || ((this.statuses != null) && this.statuses.equals(rhs.statuses)))) && ((this.sameSubject == rhs.sameSubject) || ((this.sameSubject != null) && this.sameSubject.equals(rhs.sameSubject)))) && ((this.fields == rhs.fields) || ((this.fields != null) && this.fields.equals(rhs.fields))));
    }

    @Generated("jsonschema2pojo")
    public enum LimitDisclosure {

        REQUIRED("required"), PREFERRED("preferred");
        private final static Map<String, LimitDisclosure> CONSTANTS = new HashMap<String, LimitDisclosure>();

        static {
            for (LimitDisclosure c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        LimitDisclosure(String value) {
            this.value = value;
        }

        @JsonCreator
        public static LimitDisclosure fromValue(String value) {
            LimitDisclosure constant = CONSTANTS.get(value);
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

    @Generated("jsonschema2pojo")
    public enum SubjectIsIssuer {

        REQUIRED("required"), PREFERRED("preferred");
        private final static Map<String, SubjectIsIssuer> CONSTANTS = new HashMap<String, SubjectIsIssuer>();

        static {
            for (SubjectIsIssuer c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        SubjectIsIssuer(String value) {
            this.value = value;
        }

        @JsonCreator
        public static SubjectIsIssuer fromValue(String value) {
            SubjectIsIssuer constant = CONSTANTS.get(value);
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
