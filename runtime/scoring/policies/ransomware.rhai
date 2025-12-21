// Ransomware usually performs mass file writes and deletions
// and exhibits high entropy (not calculated here yet)

print("Running Ransomware Policy against session: " + features.session_id);

if features.file_writes > 10 {
    print("Detected high volume of file writes (" + features.file_writes + ")");
    score += 50;
    rules.push("Ransomware:MassFileWrite");
}

if features.file_creates > 5 {
    score += 10;
    rules.push("Heuristic:FileDrop");
}

// Logic to determine verdict based on score accumulation
if score >= 60 {
    verdict = "Malicious";
} else if score >= 20 {
    verdict = "Suspicious";
} else {
    verdict = "Benign";
}
