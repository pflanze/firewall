# README

A typed abstraction over iptables rules, and logic to run them forward
and in reverse (for removing them again).

## Todo

* Not happy about the `Restriction` type name; rename to `Select`?

* Implement more `Restriction` features, e.g. for conntrack.

* Implement storing of the last activated rule set, so that `restart`
  can correctly de-activate the previously activated ruleset before
  working with a changed program or config to make the new ones.

