# Public contract compatibility

`consumer/v1`, `@slatefs/client`, and `@slatefs/web-components` are extend-only:
released routes, fields, tag names, properties, events, CSS parts, and CSS custom
properties are not removed, renamed, or given a different meaning within v1.
Clients ignore unknown JSON response fields. New capabilities are introduced as
new narrow interfaces or optional fields rather than new required members on an
existing capability interface.

The Rust contract test approves the OpenAPI document digest and route inventory.
The generated `custom-elements.json` is the approval snapshot for the component
surface. A deliberate contract extension updates the source contract and its
snapshot in the same reviewed change; an incompatible change requires a new
major API/package version.
