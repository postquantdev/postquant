use std::collections::HashMap;

fn main() {
    let mut scores: HashMap<String, i32> = HashMap::new();
    scores.insert("Alice".to_string(), 42);
    scores.insert("Bob".to_string(), 99);

    let names: Vec<&str> = vec!["Alice", "Bob", "Charlie"];

    for name in &names {
        match scores.get(*name) {
            Some(score) => println!("{} scored {}", name, score),
            None => println!("{} has no score", name),
        }
    }

    let total: i32 = scores.values().sum();
    println!("Total score: {}", total);
}
