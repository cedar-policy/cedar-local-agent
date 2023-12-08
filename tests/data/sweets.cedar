@id("owner-policy")
permit(principal, action, resource)
when { principal == resource.owner };

@id("admin-role-policy")
permit (
    principal in BoxRole::"admin",
    action,
    resource
);

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

@id("manager-view-edit-boxcollection-giftset")
permit (
    principal in BoxRole::"manager",
    action in [Action::"read", Action::"update"],
    resource in BoxCollection::"giftSet"
);

@id("sales-view-edit-boxgroup-christmasGiftSet")
permit (
    principal in BoxRole::"sales",
    action in [Action::"read", Action::"update"],
    resource in BoxGroup::"christmasGiftSet"
);