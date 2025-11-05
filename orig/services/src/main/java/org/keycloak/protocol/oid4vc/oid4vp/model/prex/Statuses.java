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

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "active",
        "suspended",
        "revoked"
})
@Generated("jsonschema2pojo")
public class Statuses {

    @JsonProperty("active")
    private StatusDirective active;
    @JsonProperty("suspended")
    private StatusDirective suspended;
    @JsonProperty("revoked")
    private StatusDirective revoked;

    @JsonProperty("active")
    public StatusDirective getActive() {
        return active;
    }

    @JsonProperty("active")
    public void setActive(StatusDirective active) {
        this.active = active;
    }

    @JsonProperty("suspended")
    public StatusDirective getSuspended() {
        return suspended;
    }

    @JsonProperty("suspended")
    public void setSuspended(StatusDirective suspended) {
        this.suspended = suspended;
    }

    @JsonProperty("revoked")
    public StatusDirective getRevoked() {
        return revoked;
    }

    @JsonProperty("revoked")
    public void setRevoked(StatusDirective revoked) {
        this.revoked = revoked;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Statuses.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("active");
        sb.append('=');
        sb.append(((this.active == null) ? "<null>" : this.active));
        sb.append(',');
        sb.append("suspended");
        sb.append('=');
        sb.append(((this.suspended == null) ? "<null>" : this.suspended));
        sb.append(',');
        sb.append("revoked");
        sb.append('=');
        sb.append(((this.revoked == null) ? "<null>" : this.revoked));
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
        result = ((result * 31) + ((this.active == null) ? 0 : this.active.hashCode()));
        result = ((result * 31) + ((this.revoked == null) ? 0 : this.revoked.hashCode()));
        result = ((result * 31) + ((this.suspended == null) ? 0 : this.suspended.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Statuses) == false) {
            return false;
        }
        Statuses rhs = ((Statuses) other);
        return ((((this.active == rhs.active) || ((this.active != null) && this.active.equals(rhs.active))) && ((this.revoked == rhs.revoked) || ((this.revoked != null) && this.revoked.equals(rhs.revoked)))) && ((this.suspended == rhs.suspended) || ((this.suspended != null) && this.suspended.equals(rhs.suspended))));
    }

}
