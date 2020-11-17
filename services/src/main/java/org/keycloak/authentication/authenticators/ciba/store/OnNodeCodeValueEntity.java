package org.keycloak.authentication.authenticators.ciba.store;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OnNodeCodeValueEntity {

    private final Map<String, String> notes;

    public OnNodeCodeValueEntity(Map<String, String> notes) {
        this.notes = notes == null ? Collections.EMPTY_MAP : new HashMap<>(notes);
    }

    public Map<String, String> getNotes() {
        return Collections.unmodifiableMap(notes);
    }

    public String getNote(String name) {
        return notes.get(name);
    }
}
