PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 username TEXT PRIMARY KEY,
 display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 avatar TEXT DEFAULT '',
 bio TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS follows (
 follower TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 following TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(follower,following)
);
CREATE TABLE IF NOT EXISTS posts (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 text TEXT DEFAULT '',
 image TEXT DEFAULT '',
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS likes (
 post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(post_id,username)
);
CREATE TABLE IF NOT EXISTS comments (
 id TEXT PRIMARY KEY,
 post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 display_name TEXT NOT NULL,
 avatar TEXT DEFAULT '',
 text TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
 id TEXT PRIMARY KEY,
 text TEXT NOT NULL,
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 display_name TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS presence (
 visitor_id TEXT PRIMARY KEY,
 last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
CREATE INDEX IF NOT EXISTS idx_likes_post ON likes(post_id);
