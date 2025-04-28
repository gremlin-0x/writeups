# Result of GraphQL introspection query analysis primer for red teamers

> For this primer we will be using the `introspection.json` [file](introspection.json), which contains a result of a GraphQL introspection query described in "[GraphQL API vulnerabilities](../README.md)" write-up.

Here's what we need to find: 

- __Types__: All the data types available in the API (e.g: `User`, `Int`, `String`, `Boolean`).
- __Queries__: The available queries you can perform to fetch data.
- __Mutations__: The available mutations you can perform to modify data.
- __Fields__: The fields within each type.
- __Arguments__: The arguments that _queries_ and _mutations_ can take.

The most important part of the data is its `__schema` object. Here's the top-level structure of the JSON:

```json
{
  "data": {
    "__schema": { ... }
  }
}
```

## Finding the `query` and `mutation` types

In the `__schema` object, you'll find `queryType` and `mutationType`. These tell you the names of the types that hold the query and mutation operations.

```json
    "queryType": {
      "name": "query"
    },
    "mutationType": {
      "name": "mutation"
    },
```

So basically, to start building a `query` or a `mutation`, you just need to write:

```graphql
query {
  ...
}
```

Or:

```graphql
mutation {
  ...
{
```

Respectively.

You then need to find the types with these names in the `__schema.types` array.

## Examining the `getUser` Query

Find the type named `"query"` in the `__schema.types` array.
Look at its `fields` property. You'll find a field named `"getUser"`.

```json
    {
      "kind": "OBJECT",
      "name": "query",
      "description": null,
      "fields": [
        {
          "name": "getUser",
          "description": null,
          "args": [ ... ],
          "type": { ... "name": "User" ... },
          "isDeprecated": false,
          "deprecationReason": null
        }
      ],
      ...
    }
```

__Arguments:__ The `args` property of `getUser` shows the arguments it takes.

```json
    "args": [
      {
        "name": "id",
        "description": null,
        "type": { ... "name": "Int" ... },
        "defaultValue": null
      }
    ]
```

This tells you that `getUser` takes a non-nullable argument named `id` of type `Int`.
__Return Type:__ The `type` property of `getUser` tells you the type of data it returns (`User`).
__Fields of `User`:__ To know what data you can request from `getUser`, you need to find the `User` type in `__schema.types` and look at its `fields`.

```json
    {
      "kind": "OBJECT",
      "name": "User",
      "description": null,
      "fields": [
        {
          "name": "id",
          "description": null,
          "args": [],
          "type": { ... "name": "Int" ... }
        },
        {
          "name": "username",
          "description": null,
          "args": [],
          "type": { ... "name": "String" ... }
        }
      ],
      ...
    }
```

This shows that the `User` type has fields `id` (Int) and `username` (String).

__Constructing the `getUser` Query:__
- Start with `query {`.
- Add the query name: `getUser`.
- Add the argument with a value: `(id: 1)`.
- Add the selection set (the fields you want to retrieve) within curly braces: `{ id username }`.
- Close the query: `}`.

```graphql
query {
  getUser(id: 1) {
    id
    username
  }
}
```

## Examining the `deleteOrganizationUser` Mutation

Find the type name `"mutation"` in `__schema.types`.
Look at its `fields`. You'll find a field named `"deleteOrganizationUser"`.

```json
    {
      "kind": "OBJECT",
      "name": "mutation",
      "description": null,
      "fields": [
        {
          "name": "deleteOrganizationUser",
          "description": null,
          "args": [ ... ],
          "type": { ... "name": "DeleteOrganizationUserResponse" ... }
        }
      ],
      ...
    }
```
__Arguments:__ The `args` property shows it takes an `input` argument of type `DeleteOrganizationUserInput`.

```json
    "args": [
      {
        "name": "input",
        "description": null,
        "type": { ... "name": "DeleteOrganizationUserInput" ... }
      }
    ]
```

__Input Type:__ Find the `DeleteOrganizationUserInput` type to see what fields `input` needs.

```json
    {
      "kind": "INPUT_OBJECT",
      "name": "DeleteOrganizationUserInput",
      "description": null,
      "fields": null,
      "inputFields": [
        {
          "name": "id",
          "description": null,
          "type": { ... "name": "Int" ... }
        }
      ],
      ...
    }
```

It has one field, `id` (Int).
__Return Type:__ The `type` of `deleteOrganizationUser` is `DeleteOrganizationUserResponse`. Find this type to see what data you can get back.

```json
    {
      "kind": "OBJECT",
      "name": "DeleteOrganizationUserResponse",
      "description": null,
      "fields": [
        {
          "name": "user",
          "description": null,
          "args": [],
          "type": { ... "name": "User" ... }
        }
      ],
      ...
    }
```

It has a field `user` of type `User`. You already know the fields of `User` from the `getUser` example.

__Constructing the `deleteOrganizationUser` Mutation:__
-  Start with `mutation {`.
- Add the mutation name: `deleteOrganizationUser`.
-  Add the `input` argument with a value.  Since `input` is an `INPUT_OBJECT`, its value is also an object: `(input: { id: 3 })`.
- Add the selection set. You want the `user` and its `id`: `{ user { id } }`.
- Close the mutation: `}`.

```graphql
mutation {
  deleteOrganizationUser(input: { id: 3 }) {
    user {
      id
    }
  }
}
```

## Key Takeaways

- GraphQL introspection is your guide to an API's capabilities.
- You navigate the JSON structure to find types, fields, arguments, and their relationships.
- Pay close attention to kind, name, fields, args, type, and inputFields properties.
- Use the information to construct valid GraphQL queries and mutations.

I hope this detailed explanation helps you understand how to work with GraphQL introspection data!
