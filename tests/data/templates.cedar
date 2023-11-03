// Template for permitting vacation photo access
@id("AccessVacation")
permit (
  principal in ?principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
)
when { principal has department && principal.department == "research" };


// Template for permitting vacation photo access
@id("AccessVacationTwo")
permit (
  principal in ?principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto95.jpg"
)
when { principal has department && principal.department == "research" };