package org.keycloak.authentication.authenticators.ciba.store;

import org.keycloak.common.util.Time;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OnNodeCodeValueEntity {

    private final Map<String, String> notes;
    private final int expiration;

    public OnNodeCodeValueEntity(Map<String, String> notes, int lifespanSeconds) {
        this.expiration = Time.currentTime() + lifespanSeconds * 1000;
        this.notes = notes == null ? Collections.EMPTY_MAP : new HashMap<>(notes);
    }

    public Map<String, String> getNotes() {
        return Collections.unmodifiableMap(notes);
    }

    public String getNote(String name) {
        return notes.get(name);
    }

    public int getExpiration() {
        return expiration;
    }
}
