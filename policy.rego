package rules


users := {
    "alice":   {"manager": "charlie", "title": "salesperson"},
    "bob":     {"manager": "charlie", "title": "salesperson"},
    "charlie": {"manager": "dave",    "title": "manager"},
    "dave":    {"manager": null,      "title": "ceo"}
}

default allow = false


user_is_employee {
    users[input.user]
}

user_is_manager {
  u := users[input.user]
  not u.title == "salesperson"
}


allow {
 user_is_employee
    input.path = ["cars", carId]
    input.method == "GET"
}

allow {
 user_is_employee
    input.path = ["cars", carId, "status"]
    input.method == "GET"
}

allow {
 user_is_employee
    input.path = ["cars", carId, "status"]
    input.method == "POST"
}

allow {
 user_is_manager
    input.path == ["cars"]
    input.method == "POST"
}

allow {
 user_is_manager
    input.path = ["cars", carId]
    input.method == "PUT"
}

allow {
 user_is_manager
    input.path = ["cars", carId]
    input.method == "DELETE"
}

allow {
  input.path == ["cars"]
  input.method == "GET"
}
