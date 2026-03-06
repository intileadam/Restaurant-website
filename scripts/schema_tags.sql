-- Customer tags for campaign console.
-- Run once per database (tags are shared across CUSTOMERS / TESTCUSTOMERS).
-- Requires existing CUSTOMERS (and optionally TESTCUSTOMERS) tables.

CREATE TABLE IF NOT EXISTS tags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(191) NOT NULL,
  UNIQUE KEY tags_name_unique (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS customer_tags (
  customer_table VARCHAR(64) NOT NULL,
  custid INT NOT NULL,
  tag_id INT NOT NULL,
  PRIMARY KEY (customer_table, custid, tag_id),
  KEY customer_tags_tag_id (tag_id),
  CONSTRAINT customer_tags_tag_fk
    FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
