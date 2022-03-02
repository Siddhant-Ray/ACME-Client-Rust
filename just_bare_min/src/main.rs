use std::io;

fn main() {
    println!("Seems like I like Python more still!");
    println!(" Will do something here soon");

    let mut var = String::new();

    io::stdin()
        .read_line(&mut var)
        .expect("Can't even get IO to work? ");

    println!("Well I enetered whatever I want here : {}", var);
}
