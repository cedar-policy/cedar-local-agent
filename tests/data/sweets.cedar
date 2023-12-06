@id("owner-policy")
permit(principal, action, resource)
when { principal == resource.owner };

@id("mike-edit-box-1")
permit (
    principal == User::"Mike",
    action == Action::"update",
    resource == Box::"1"
);

@id("mike-view-box-2")
permit (
    principal == User::"Mike",
    action == Action::"read",
    resource == Box::"2"
);

@id("eric-view-box-9")
permit (
    principal == User::"Eric",
    action == Action::"read",
    resource == Box::"9"
);

@id("eric-edit-box-10")
permit (
    principal == User::"Eric",
    action == Action::"update",
    resource == Box::"10"
);

@id("boxmanagers-edit-box")
permit (
    principal in Role::"boxManagers",
    action == Action::"update",
    resource in Group::"boxGroup"
);