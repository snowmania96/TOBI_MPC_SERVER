USE mydatabase;
-- Create the necessary tables for the Auth layer and DKLs23 layer to keep their data.

-- Auth layer:
CREATE TABLE Accounts (
    userid VARCHAR(255) PRIMARY KEY,
    account_type VARCHAR(255),
    UNIQUE (userid)
);

CREATE TABLE Passkeys (
    userid VARCHAR(255),
    credential_id VARCHAR(255),
    credential JSON,
    FOREIGN KEY (userid) REFERENCES Accounts(userid)
);

CREATE TABLE OAuth2 (
    userid VARCHAR(255),
    provider VARCHAR(255),
    provider_uid VARCHAR(255),
    PRIMARY KEY (userid, provider),
    FOREIGN KEY (userid) REFERENCES Accounts(userid)
);


-- DKLs23 layer:
CREATE TABLE DKLs (
    publickey VARCHAR(255) PRIMARY KEY,
    userid VARCHAR(255),
    FOREIGN KEY (userid) REFERENCES Accounts(userid)
);

CREATE TABLE QuorumWhitelist (
    userid VARCHAR(255),
    publickey VARCHAR(255),
    participants TEXT,
    datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- use hash of the participants column for indexing, store as a binary for performance
    participants_hash BINARY(32) AS (UNHEX(SHA2(participants, 256))),
    FOREIGN KEY (userid) REFERENCES Accounts(userid),
    UNIQUE (userid, publickey, participants_hash)
);

DELIMITER //

CREATE PROCEDURE InsertQuorumWhitelist(IN _userid VARCHAR(255), IN _publickey VARCHAR(255), IN _participants TEXT, IN _whitelist_history INT)
BEGIN
    -- Declare a variable to store the threshold datetime
    DECLARE threshold_datetime DATETIME;
    DECLARE _offset INT;

    -- Insert the new record into QuorumWhitelist
    INSERT INTO QuorumWhitelist (userid, publickey, participants) VALUES (_userid, _publickey, _participants);

    -- Set the threshold datetime by selecting the nth recent datetime
    SET _offset = _whitelist_history - 1;
    SET threshold_datetime = (SELECT datetime
                              FROM QuorumWhitelist
                              WHERE userid = _userid
                              ORDER BY datetime DESC
                              LIMIT 1 OFFSET _offset);

    -- Delete records that are older than the threshold datetime
    IF threshold_datetime IS NOT NULL THEN
        DELETE FROM QuorumWhitelist
        WHERE userid = _userid AND datetime < threshold_datetime;
    END IF;
END //

DELIMITER ;