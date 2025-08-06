package main

import (
	"database/sql"

	_ "modernc.org/sqlite" // import only the sql-driver
)

func initDatabase(dbPath string) error {
	var err error
	logf("Database at: %s", dbPath)
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}

	// Create table if not exists
	query := `
	CREATE TABLE IF NOT EXISTS requests (
		timestamp INTEGER PRIMARY KEY,
		method TEXT,
		url TEXT,
		request BLOB,
		response BLOB
	);
	CREATE INDEX IF NOT EXISTS idx_method ON requests(method);
	CREATE INDEX IF NOT EXISTS idx_url ON requests(url);
	`
	_, err = db.Exec(query)
	if err != nil {
		return err
	}

	// Initialize capture channel and worker
	// this channel has 124 slots, i.e., it must be higher for heavy traffic apps
	captureChan = make(chan *CaptureData, 124)
	saveWg.Add(1)
	go saveWorker()
	return nil
}

func saveWorker() {
	defer saveWg.Done()
	for data := range captureChan {
		if config.Verbose {
			debugCapturedData(data)
		}
		if err := saveToDatabase(data); err != nil {
			debugf("Failed to save to database: %v", err)
		}
	}
}

func saveToDatabase(data *CaptureData) error {
	_, err := db.Exec(
		"INSERT INTO requests (timestamp, method, url, request, response) VALUES (?, ?, ?, ?, ?)",
		data.Timestamp, data.Method, data.URL, data.Request, data.Response,
	)
	return err
}

func closeDatabase() {
	if captureChan != nil {
		close(captureChan)
		saveWg.Wait()
	}
	if db != nil {
		db.Close()
	}
}
