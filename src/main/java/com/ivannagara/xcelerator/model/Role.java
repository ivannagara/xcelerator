package com.ivannagara.xcelerator.model;

public enum Role {
    SUPER_ADMIN,
    ADMIN,
    STAFF;

    public boolean hasPermissionLevel(Role role) {
        if (this == SUPER_ADMIN) return true;
        if (this == ADMIN) return role != SUPER_ADMIN;
        return role == STAFF;
    }
}


