// Everyone can view the photos in the "jane_vacation" album
// (and list the photos in the album)
@id("jane_vacation public")
permit (
  principal,
  action in [Action::"view", Action::"listPhotos"],
  resource in Album::"jane_vacation"
);

// Template for permitting vacation photo access
@id("AccessVacation")
permit (
  principal in ?principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
)
when { principal has department && principal.department == "research" };

// Template for permitting vacation photo access
@id("AccessVacation")
permit (
  principal in ?principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
)
when { principal has department && principal.department == "research" };