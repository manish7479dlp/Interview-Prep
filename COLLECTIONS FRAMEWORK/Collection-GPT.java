 What is Java Collections Framework?
   A unified architecture to store, retrieve, and manipulate groups of objects.
   Includes interfaces, implementations (classes), and algorithms


| Interface    | Description                                        | Example Classes                                    |
| ------------ | -------------------------------------------------- | -------------------------------------------------- |
| `Collection` | Root interface of the collection hierarchy         | -                                                  |
| `List`       | Ordered collection with duplicates allowed         | `ArrayList`, `LinkedList`, `Vector`, `Stack`       |
| `Set`        | Unordered collection with **no duplicates**        | `HashSet`, `LinkedHashSet`, `TreeSet`              |
| `Queue`      | Designed for holding elements prior to processing  | `PriorityQueue`, `ArrayDeque`                      |
| `Deque`      | Double-ended queue                                 | `ArrayDeque`, `LinkedList`                         |
| `Map`        | Key-value pairs (not part of Collection interface) | `HashMap`, `LinkedHashMap`, `TreeMap`, `Hashtable` |

🔹 3. List Interface
Allows duplicates, maintains insertion order.

Access via index.

✅ Implementations:
ArrayList – Fast read, slow insert/delete.

LinkedList – Fast insert/delete, slow access.

Vector – Synchronized (thread-safe).

Stack – LIFO (extends Vector).

4. Set Interface
No duplicates, unordered (except LinkedHashSet).

✅ Implementations:
HashSet – Uses hash table, no order guaranteed.

LinkedHashSet – Maintains insertion order.

TreeSet – Sorted (uses Red-Black Tree), implements NavigableSet.

🔹 5. Queue and Deque
Queue: FIFO structure.

PriorityQueue – Ordered based on comparator/natural ordering.

Deque: Double-ended queue.

ArrayDeque – Resizable array.


 6. Map Interface (Key-Value Pairs)
Not a subtype of Collection.

| Class               | Ordering        | Null Keys/Values             | Thread-Safe    |
| ------------------- | --------------- | ---------------------------- | -------------- |
| `HashMap`           | No order        | 1 null key, many null values | ❌              |
| `LinkedHashMap`     | Insertion order | ✔                            | ❌              |
| `TreeMap`           | Sorted by keys  | ❌ (null keys)                | ❌              |
| `Hashtable`         | No order        | ❌                            | ✔              |
| `ConcurrentHashMap` | No order        | ❌                            | ✔ (Concurrent) |


// Differences Table

| Feature          | ArrayList | LinkedList | HashSet | TreeSet | HashMap    |
| ---------------- | --------- | ---------- | ------- | ------- | ---------- |
| Order Maintained | Yes       | Yes        | No      | Sorted  | No         |
| Duplicates       | Yes       | Yes        | No      | No      | No keys    |
| Nulls Allowed    | Yes       | Yes        | 1 null  | ❌       | 1 null key |
| Thread-safe      | ❌         | ❌          | ❌       | ❌       | ❌          |


// 8. Sorting Collections

Collections.sort(list); // Natural order
Collections.sort(list, comparator); // Custom order


//  9. Iterating Collections

for (String s : list) { }          // Enhanced for-loop
Iterator<String> it = list.iterator();
while (it.hasNext()) { it.next(); }
list.forEach(System.out::println); // Java 8+

// 10. Java 8 Stream API with Collections

list.stream()
    .filter(e -> e.startsWith("A"))
    .map(String::toUpperCase)
    .sorted()
    .forEach(System.out::println);


// 🔹 11. Thread-safe Alternatives

| Non-thread-safe | Thread-safe Alternative |
| --------------- | ----------------------- |
| `ArrayList`     | `CopyOnWriteArrayList`  |
| `HashMap`       | `ConcurrentHashMap`     |
| `HashSet`       | `CopyOnWriteArraySet`   |


🔹 12. When to Use What

ArrayList: When you need fast random access and less insert/delete.

LinkedList: When frequent insert/delete operations are needed.

HashSet: When unique items without order are needed.

TreeSet: When you need sorted unique elements.

HashMap: For fast key-value lookups.

TreeMap: For sorted keys.

ConcurrentHashMap: For thread-safe key-value storage.





