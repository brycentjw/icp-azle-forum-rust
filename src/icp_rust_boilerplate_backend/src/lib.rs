#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api;
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

// Enums

// Traits

// Structs

// Message Struct
#[derive(candid::CandidType, Deserialize, Serialize, Clone)]
struct Post {
    id: u64,
    content: String,
    is_deleted: bool,
    author: String,
    likes: Vec<String>,
    topic_id: u64,
    category_id: u64,
    content_edit_history: HashMap<u64, String>, // Key: timestamp, Value: content
}

// Topic Struct
#[derive(candid::CandidType, Deserialize, Serialize, Clone)]
struct Topic {
    id: u64,
    title: String,
    content: String,
    posts: HashMap<u64, Post>,
    is_pinned: bool,
    is_closed: bool,
    author: String,
    likes: Vec<String>,
    category_id: u64,
    content_edit_history: HashMap<u64, String>, // Key: timestamp, Value: content
    title_edit_history: HashMap<u64, String>,   // Key: timestamp, Value: content
    most_recent_activity: u64,                  // timestamp
}

// Category Struct
#[derive(candid::CandidType, Deserialize, Serialize, Clone)]
struct Category {
    id: u64,
    name: String,
    topics: HashMap<u64, Topic>,
    pinned_topics: Vec<u64>,
    most_recent_topics: Vec<u64>,
    created_at: u64,
    author: String,
}

// a trait that must be implemented for a struct that is stored in a stable struct
impl Storable for Category {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

// another trait that must be implemented for a struct that is stored in a stable struct
impl BoundedStorable for Category {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static CATEGORY_STORAGE: RefCell<StableBTreeMap<u64, Category, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    // Stores the admin addresses
    static ADMIN_ADDRESSES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    // Stores the moderator addresses
    static MODERATOR_ADDRESSES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    // Stores the addresses of banned users
    static BANNED_ADDRESSES: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

// Payload Definitions

// Category Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct CategoryPayload {
    name: String,
}

// Topic Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct TopicPayload {
    title: String,
    content: String,
    category_id: String,
}

// Post Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct PostPayload {
    content: String,
}

// Get all categories
#[ic_cdk::query]
fn get_all_categories() -> Result<Vec<Category>, Error> {
    CATEGORY_STORAGE.with(|storage| {
        let stable_btree_map = &*storage.borrow();
        let records: Vec<Category> = stable_btree_map
            .iter()
            .map(|(_, category)| category.clone())
            .collect();
        if records.is_empty() {
            return Err(Error::NotFound {
                msg: "No categories found".to_string(),
            });
        }
        Ok(records)
    })
}

// Get all topic IDs of a category ID
// Pinned topics appear first, followed by topics with most recent activity
#[ic_cdk::query]
fn get_all_topics_in_category(category_id: u64) -> Result<HashMap<u64, Topic>, Error> {
    match _get_topics(&category_id) {
        Some(topics) => Ok(topics),
        None => Err(Error::NotFound {
            msg: "No topics found".to_string(),
        }),
    }
}

// Get the specified topic
#[ic_cdk::query]
fn get_topic(category_id: u64, topic_id: u64) -> Result<Topic, Error> {
    match _get_topic(&category_id, &topic_id) {
        Some(topic) => Ok(topic),
        None => Err(Error::NotFound {
            msg: "Topic not found".to_string(),
        }),
    }
}

// Get the specified post
#[ic_cdk::query]
fn get_post(category_id: u64, topic_id: u64, postid: u64) -> Result<Post, Error> {
    match _get_post(&category_id, &topic_id, &postid) {
        Some(topics) => Ok(topics),
        None => Err(Error::NotFound {
            msg: "Post not found".to_string(),
        }),
    }
}

// Get all moderators
#[ic_cdk::query]
fn get_all_moderators() -> Result<Vec<String>, Error> {
    let moderators =
        MODERATOR_ADDRESSES.with(|moderator_addresses| moderator_addresses.lock().unwrap().clone());
    Ok(moderators)
}

// Get all admins
#[ic_cdk::query]
fn get_all_admins() -> Result<Vec<String>, Error> {
    let admins = ADMIN_ADDRESSES.with(|admin_addresses| admin_addresses.lock().unwrap().clone());
    Ok(admins)
}

// Get all banned addresses
#[ic_cdk::query]
fn get_all_banned_addresses() -> Result<Vec<String>, Error> {
    let banned_addresses =
        BANNED_ADDRESSES.with(|banned_addresses| banned_addresses.lock().unwrap().clone());
    Ok(banned_addresses)
}

// Create a category
// Should only be accessible to admins
#[ic_cdk::update]
fn create_category(category: CategoryPayload) -> Result<Category, Error> {
    let caller: String = api::caller().to_string();
    let is_admin = _check_if_admin(&caller);
    
    // Validate the payload
    if category.name.is_empty() {
        return Err(Error::InvalidPayload(
            "Category 'name' cannot be empty.".to_string(),
        ));
    }

    if is_admin {
        let id = _get_id();
        let category = Category {
            id: id,
            name: category.name,
            topics: HashMap::new(),
            pinned_topics: vec![],
            most_recent_topics: vec![],
            created_at: time(),
            author: caller,
        };
        CATEGORY_STORAGE.with(|service| service.borrow_mut().insert(category.id, category.clone()));
        Ok(category)
    } else {
        Err(Error::UnAuthorized {
            msg: "Only an admin can create a category".to_string(),
        })
    }
}

// Create a topic for a specific category
#[ic_cdk::update]
fn create_topic(category_id: u64, topic: TopicPayload) -> Result<Topic, Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    // Validate the payload
    if topic.title.is_empty() {
        return Err(Error::InvalidPayload(
            "Topic 'title' cannot be empty.".to_string(),
        ));
    }
    if topic.content.is_empty() {
        return Err(Error::InvalidPayload(
            "Topic 'content' cannot be empty.".to_string(),
        ));
    }

    if !is_banned {
        let id = _get_id();
        let topic = Topic {
            id: id,
            title: topic.title,
            content: topic.content,
            posts: HashMap::new(),
            is_pinned: false,
            is_closed: false,
            author: caller,
            likes: vec![],
            category_id: category_id,
            content_edit_history: HashMap::new(),
            title_edit_history: HashMap::new(),
            most_recent_activity: time(),
        };

        let mut category = _get_category(&category_id).unwrap();
        category.topics.insert(id, topic.clone());

        _acknowledge_topic_activity(&category_id, &id);

        Ok(topic)
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to create topics".to_string(),
        })
    }
}

// Post on a specific topic
#[ic_cdk::update]
fn create_post(category_id: u64, topic_id: u64, post: PostPayload) -> Result<Post, Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    // Validate the payload
    if post.content.is_empty() {
        return Err(Error::InvalidPayload(
            "Post 'content' cannot be empty.".to_string(),
        ));
    }

    if !is_banned {
        let id = _get_id();
        let post = Post {
            id: id,
            content: post.content,
            is_deleted: false,
            author: caller,
            likes: vec![],
            topic_id: topic_id,
            category_id: category_id,
            content_edit_history: HashMap::new(),
        };

        let mut topic = _get_topic(&category_id, &topic_id).unwrap();
        topic.posts.insert(id, post.clone());

        Ok(post)
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to create posts".to_string(),
        })
    }
}

// Like a topic
#[ic_cdk::update]
fn like_topic(category_id: u64, topic_id: u64) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    if !is_banned {
        let topic = _get_topic(&category_id, &topic_id).unwrap();
        match _like_or_unlike_message(Either::Left(topic), &caller, true) {
            Ok(()) => Ok(()),
            Err(error_message) => Err(Error::InternalServerError {
                msg: (error_message),
            }),
        }
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to like topics".to_string(),
        })
    }
}

// Like a post
#[ic_cdk::update]
fn like_post(category_id: u64, topic_id: u64, post_id: u64) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    if !is_banned {
        let post = _get_post(&category_id, &topic_id, &post_id).unwrap();
        match _like_or_unlike_message(Either::Right(post), &caller, true) {
            Ok(()) => Ok(()),
            Err(error_message) => Err(Error::InternalServerError {
                msg: (error_message),
            }),
        }
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to like posts".to_string(),
        })
    }
}

// Edit an existing topic
#[ic_cdk::update]
fn edit_topic(category_id: u64, topic_id: u64, new_content: String) -> Result<String, Error> {
    let caller: String = api::caller().to_string();

    let is_banned = _check_if_banned(&caller);

    let topic = _get_topic(&category_id, &topic_id).unwrap();
    let is_author = topic.author == caller;

    if !is_banned && is_author {
        match _edit_content(Either::Left(topic), &new_content) {
            Ok(()) => Ok(new_content),
            Err(error_message) => Err(Error::InternalServerError {
                msg: (error_message),
            }),
        }
    } else if is_banned {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to edit topics".to_string(),
        })
    } else {
        Err(Error::UnAuthorized {
            msg: "You must be the author of this topic to edit it".to_string(),
        })
    }
}

// Edit an existing post
#[ic_cdk::update]
fn edit_post(
    category_id: u64,
    topic_id: u64,
    post_id: u64,
    new_content: String,
) -> Result<String, Error> {
    let caller: String = api::caller().to_string();

    let is_banned = _check_if_banned(&caller);

    let post = _get_post(&category_id, &topic_id, &post_id).unwrap();
    let is_author = post.author == caller;

    if !is_banned && is_author {
        match _edit_content(Either::Right(post), &new_content) {
            Ok(()) => Ok(new_content),
            Err(error_message) => Err(Error::InternalServerError {
                msg: (error_message),
            }),
        }
    } else if is_banned {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to edit posts".to_string(),
        })
    } else if !is_author {
        Err(Error::UnAuthorized {
            msg: "You must be the author of this post to edit it".to_string(),
        })
    } else {
        Err(Error::UnAuthorized {
            msg: "This post has been deleted and cannot be edited".to_string(),
        })
    }
}

// Pin or unpin an existing topic
#[ic_cdk::update]
fn pin_or_unpin_topic(category_id: u64, topic_id: u64, should_pin: bool) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    if !is_banned {
        let mut topic = _get_topic(&category_id, &topic_id).unwrap();
        topic.is_pinned = should_pin;
        Ok(())
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to like topics".to_string(),
        })
    }
}

// Close or open an existing topic
#[ic_cdk::update]
fn open_or_close_topic(category_id: u64, topic_id: u64, should_close: bool) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    if !is_banned {
        let mut topic = _get_topic(&category_id, &topic_id).unwrap();
        topic.is_closed = should_close;
        Ok(())
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to like topics".to_string(),
        })
    }
}

// Add an address as a moderator
#[ic_cdk::update]
fn add_moderator(address: String) -> Result<(), Error> {
    let caller: String = api::caller().to_string();

    match _add_moderator(&address, &caller) {
        Ok(()) => Ok(()),
        Err(error_message) => Err(Error::UnAuthorized {
            msg: (error_message),
        }),
    }
}

// Add an address as an admin
#[ic_cdk::update]
fn add_admin(address: String) -> Result<(), Error> {
    let caller: String = api::caller().to_string();

    match _add_admin(&address, &caller) {
        Ok(()) => Ok(()),
        Err(error_message) => Err(Error::UnAuthorized {
            msg: (error_message),
        }),
    }
}

// Ban address
#[ic_cdk::update]
fn ban_address(address: String) -> Result<(), Error> {
    let caller: String = api::caller().to_string();

    match _ban_address(&address, &caller) {
        Ok(()) => Ok(()),
        Err(error_message) => Err(Error::UnAuthorized {
            msg: (error_message),
        }),
    }
}

// Delete a category
#[ic_cdk::update]
fn delete_category(category_id: u64) -> Result<Category, Error> {
    match CATEGORY_STORAGE.with(|service| service.borrow().get(&category_id)) {
        Some(category) => {
            let caller = api::caller().to_string();

            // Checks if the caller is an admin
            let is_admin = _check_if_admin(&caller);

            // Remove the course from storage
            if is_admin {
                CATEGORY_STORAGE.with(|service| service.borrow_mut().remove(&category_id));
                Ok(category)
            } else {
                Err(Error::UnAuthorized {
                    msg: format!(
                        "You are not authorized to delete category with id={}",
                        category_id
                    ),
                })
            }
        }
        None => Err(Error::NotFound {
            msg: format!(
                "couldn't delete a category with id={}. course not found",
                category_id
            ),
        }),
    }
}

// Delete a post
#[ic_cdk::update]
fn delete_post(category_id: u64, topic_id: u64, post_id: u64) -> Result<(), Error> {
    let caller: String = api::caller().to_string();

    let is_banned = _check_if_banned(&caller);

    let post = _get_post(&category_id, &topic_id, &post_id).unwrap();
    let is_authorized = _check_if_authorized(&post.author, &caller);

    if !is_banned && is_authorized {
        let mut post = _get_post(&category_id, &topic_id, &post_id).unwrap();
        post.content = String::new();
        post.content_edit_history.clear();
        post.is_deleted = true;
        Ok(())
    } else if is_banned {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to delete posts".to_string(),
        })
    } else {
        Err(Error::UnAuthorized {
            msg: "You must be the author, an admin or a moderator to delete posts".to_string(),
        })
    }
}

// Remove an address as a moderator
#[ic_cdk::update]
fn remove_moderator(address: String) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    match _remove_moderator(&address, &caller) {
        Ok(()) => Ok(()),
        Err(error_message) => Err(Error::UnAuthorized {
            msg: (error_message),
        }),
    }
}

// Remove an address as an admin
#[ic_cdk::update]
fn remove_admin(address: String) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    match _remove_admin(&address, &caller) {
        Ok(()) => Ok(()),
        Err(error_message) => Err(Error::UnAuthorized {
            msg: (error_message),
        }),
    }
}

// Unban an address
#[ic_cdk::update]
fn unban_address(address: String) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    match _unban_address(&address, &caller) {
        Ok(()) => Ok(()),
        Err(error_message) => Err(Error::UnAuthorized {
            msg: (error_message),
        }),
    }
}

// Remove a like from a topic
#[ic_cdk::update]
fn remove_like_from_topic(category_id: u64, topic_id: u64) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    if !is_banned {
        let topic = _get_topic(&category_id, &topic_id).unwrap();
        match _like_or_unlike_message(Either::Left(topic), &caller, false) {
            Ok(()) => Ok(()),
            Err(_) => Ok(()),
        }
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to unlike topics".to_string(),
        })
    }
}

// Remove a like from a post
#[ic_cdk::update]
fn remove_like_from_post(category_id: u64, topic_id: u64, post_id: u64) -> Result<(), Error> {
    let caller: String = api::caller().to_string();
    let is_banned = _check_if_banned(&caller);

    if !is_banned {
        let post = _get_post(&category_id, &topic_id, &post_id).unwrap();
        match _like_or_unlike_message(Either::Right(post), &caller, false) {
            Ok(()) => Ok(()),
            Err(_) => Ok(()),
        }
    } else {
        Err(Error::BannedUser {
            msg: "Banned addresses are not authorized to unlike posts".to_string(),
        })
    }
}

// Error types
#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    UnAuthorized { msg: String },
    EmptyFields { msg: String },
    BannedUser { msg: String },
    InternalServerError { msg: String },
}

enum Either<A, B> {
    Left(A),
    Right(B),
}

// Internal Helper Functions

// Get a specific category/topic/post
fn _get_category(category_id: &u64) -> Option<Category> {
    CATEGORY_STORAGE.with(|service| service.borrow().get(category_id))
}

fn _get_topics(category_id: &u64) -> Option<HashMap<u64, Topic>> {
    match _get_category(category_id) {
        Some(category) => Some(category.topics),
        None => None,
    }
}

fn _get_topic(category_id: &u64, topic_id: &u64) -> Option<Topic> {
    match _get_topics(category_id) {
        Some(ref topics) => topics.get(topic_id).cloned(), // expected enum `std:;option::Option<Topic>`, found enum `std::option::Option<&_>`
        None => None,
    }
}

fn _get_posts(category_id: &u64, topic_id: &u64) -> Option<HashMap<u64, Post>> {
    match _get_topic(category_id, topic_id) {
        Some(topic) => Some(topic.posts),
        None => None,
    }
}

fn _get_post(category_id: &u64, topic_id: &u64, postid: &u64) -> Option<Post> {
    match _get_posts(category_id, topic_id) {
        Some(ref posts) => posts.get(postid).cloned(),
        None => None,
    }
}

// Acknowledge topic activity
fn _acknowledge_topic_activity(category_id: &u64, topic_id: &u64) -> bool {
    let mut category = _get_category(category_id).unwrap();
    let mut topic = _get_topic(category_id, topic_id).unwrap();
    // Update the most recent activity timestamp for the topic
    topic.most_recent_activity = time();

    // Find the index of the topic in the most_recent_topics list
    if let Some(most_recent_topic_index) = category
        .most_recent_topics
        .iter()
        .position(|element| element == &topic.id)
    {
        // Remove the topic from the most_recent_topics list
        category.most_recent_topics.remove(most_recent_topic_index);
    }

    // Add the topic to the front of the most_recent_topics list
    category.most_recent_topics.insert(0, topic.id);

    true
}

// Sort topics by activity and pin status
fn _sort_topics_by_activity_and_pin(category: &Category) -> Vec<u64> {
    // Combine pinned topics and most recent topics
    let mut sorted_topics: Vec<u64> = category.pinned_topics.clone();
    sorted_topics.extend(category.most_recent_topics.clone());

    // Use a HashSet to filter out duplicates while maintaining order
    let mut unique_sorted_topics = Vec::new();
    let mut seen = HashSet::new();

    for topic_id in sorted_topics {
        if seen.insert(topic_id) {
            unique_sorted_topics.push(topic_id);
        }
    }

    unique_sorted_topics
}

// Like or unlike a message
fn _like_or_unlike_message(
    mut post_or_topic: Either<Topic, Post>,
    caller: &String,
    should_like: bool,
) -> Result<(), String> {
    // Helper function to handle the like/unlike logic
    fn handle_like_unlike(
        likes: &mut Vec<String>,
        caller: &String,
        should_like: bool,
    ) -> Result<(), String> {
        let caller_index = likes.iter().position(|element| element == caller);

        if should_like {
            if caller_index.is_none() {
                likes.push(caller.clone());
                Ok(())
            } else {
                Err("Already liked".to_string())
            }
        } else {
            if let Some(index) = caller_index {
                likes.remove(index);
                Ok(())
            } else {
                Err("Already unliked".to_string())
            }
        }
    }

    match post_or_topic {
        Either::Left(ref mut topic) => handle_like_unlike(&mut topic.likes, caller, should_like),
        Either::Right(ref mut post) => handle_like_unlike(&mut post.likes, caller, should_like),
    }
}

// Edit message
fn _edit_content(
    mut post_or_topic: Either<Topic, Post>,
    new_content: &String,
) -> Result<(), String> {
    let timestamp = time();
    match post_or_topic {
        Either::Left(ref mut topic) => {
            // Push the old content into the edit history
            topic
                .content_edit_history
                .insert(timestamp, topic.content.clone());
            // Update the content with the new content
            topic.content = new_content.to_string();
        }
        Either::Right(ref mut post) => {
            // Push the old content into the edit history
            post.content_edit_history
                .insert(timestamp, post.content.clone());
            // Update the content with the new content
            post.content = new_content.to_string();
        }
    }
    Ok(())
}

// Edit title
fn _edit_title(mut topic: Topic, new_title: String) -> Result<(), String> {
    topic.title = new_title;
    Ok(())
}

// Validate the category input
fn _validate_category_input() -> Result<(), String> {
    Err("Currently unimplemented".to_string())
}

// Checks if the caller is either the creator, an admin, or a moderator
fn _check_if_authorized(creator_address: &String, caller: &String) -> bool {
    _check_if_admin(caller) || _check_if_moderator(caller) || caller == creator_address
}

// Get and increment ID_COUNTER
fn _get_id() -> u64 {
    ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("cannot increment id counter")
}

// Administrative functions

// Validate the input to be the admin
fn _check_if_admin(address: &String) -> bool {
    let admins = ADMIN_ADDRESSES.with(|admin_addresses| admin_addresses.lock().unwrap().clone());
    admins.contains(&address.to_string())
}

// Validate the input to be a moderator
fn _check_if_moderator(address: &String) -> bool {
    let moderators =
        MODERATOR_ADDRESSES.with(|moderator_addresses| moderator_addresses.lock().unwrap().clone());
    moderators.contains(&address.to_string())
}

// Check whether the address is banned
fn _check_if_banned(address: &String) -> bool {
    let banned_addresses =
        BANNED_ADDRESSES.with(|banned_addresses| banned_addresses.lock().unwrap().clone());
    banned_addresses.contains(&address.to_string())
}

// Add admin
fn _add_admin(address: &String, caller: &String) -> Result<(), String> {
    // Check if the caller is admin
    let is_admin = _check_if_admin(&caller);

    if is_admin {
        let result = ADMIN_ADDRESSES.with(|admin_addresses| {
            let mut addresses = admin_addresses.lock().unwrap();

            // Check if the admin address already exists
            if addresses.contains(address) {
                return Err("Admin address already exists".to_string());
            }

            addresses.push(address.to_string());
            Ok(())
        });
        result
    } else {
        Err("Only admins can add admins".to_string())
    }
}

// Add moderator
fn _add_moderator(address: &String, caller: &String) -> Result<(), String> {
    // Check if the caller is admin
    let is_admin = _check_if_admin(&caller);

    if is_admin {
        let result = MODERATOR_ADDRESSES.with(|moderator_addresses| {
            let mut addresses = moderator_addresses.lock().unwrap();

            // Check if the moderator address already exists
            if addresses.contains(address) {
                return Err("Moderator address already exists".to_string());
            }

            addresses.push(address.to_string());
            Ok(())
        });
        result
    } else {
        Err("Only admins can add moderators".to_string())
    }
}

// Remove an admin
fn _remove_admin(address: &String, caller: &String) -> Result<(), String> {
    // Check if the caller is admin
    let is_admin: bool = _check_if_admin(&caller);

    if is_admin {
        let result = ADMIN_ADDRESSES.with(|admin_addresses| {
            let mut addresses: std::sync::MutexGuard<'_, Vec<String>> =
                admin_addresses.lock().unwrap();
            // Check if the admin address exists
            if addresses.contains(&address) {
                addresses.retain(|a| a != address);
                Ok(())
            } else {
                Err("Provided address is not an admin".to_string())
            }
        });
        result
    } else {
        Err("only admins can remove admins".to_string())
    }
}

// Remove a moderator
fn _remove_moderator(address: &String, caller: &String) -> Result<(), String> {
    // Check if the caller is admin
    let is_admin: bool = _check_if_admin(&caller);

    if is_admin {
        let result = MODERATOR_ADDRESSES.with(|moderator_addresses| {
            let mut addresses: std::sync::MutexGuard<'_, Vec<String>> =
                moderator_addresses.lock().unwrap();
            // Check if the admin address exists
            if addresses.contains(&address) {
                addresses.retain(|a| a != address);
                Ok(())
            } else {
                Err("Provided address is not a moderator".to_string())
            }
        });
        result
    } else {
        Err("only admins can remove moderators".to_string())
    }
}

// Ban an address
fn _ban_address(address: &String, caller: &String) -> Result<(), String> {
    // Check if the caller is admin
    let is_admin = _check_if_admin(&caller);

    if is_admin {
        let result = BANNED_ADDRESSES.with(|banned_addresses| {
            let mut addresses = banned_addresses.lock().unwrap();

            // Check if the banned address already exists
            if addresses.contains(&address) {
                return Err("Admin address already exists".to_string());
            }

            addresses.push(address.to_string());
            Ok(())
        });
        result
    } else {
        Err("Only admins can ban addresses".to_string())
    }
}

// Unban an address
fn _unban_address(address: &String, caller: &String) -> Result<(), String> {
    // Check if the caller is an admin
    let is_admin: bool = _check_if_admin(&caller);
    // Check if the caller is a moderator
    let is_moderator: bool = _check_if_moderator(&caller);

    if is_admin | is_moderator {
        let result = BANNED_ADDRESSES.with(|banned_addresses| {
            let mut addresses: std::sync::MutexGuard<'_, Vec<String>> =
                banned_addresses.lock().unwrap();
            // Check if the banned address exists
            if addresses.contains(&address) {
                addresses.retain(|a| a != address);
                Ok(())
            } else {
                Err("Provided address is not banned".to_string())
            }
        });
        result
    } else {
        Err("only admins can unban".to_string())
    }
}

// need this to generate candid
ic_cdk::export_candid!();