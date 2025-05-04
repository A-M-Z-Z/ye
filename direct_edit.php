<?php
session_start();

// Security check
if (!isset($_SESSION['username']) || !isset($_SESSION['user_id'])) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

// Database Connection
$host = 'localhost';
$user = 'root';
$pass = 'root';
$dbname = 'cloudbox';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit();
}

$userid = $_SESSION['user_id'];

// Get file content directly without type checking
if (isset($_GET['file_id']) && is_numeric($_GET['file_id'])) {
    $fileId = intval($_GET['file_id']);
    
    $stmt = $conn->prepare("SELECT f.filename, f.file_type, fc.content 
                        FROM files f 
                        JOIN file_content fc ON f.id = fc.file_id 
                        WHERE f.id = ? AND (f.user_id = ? OR f.id IN (SELECT file_id FROM shared_files WHERE shared_with = ?))");
    $stmt->bind_param("iii", $fileId, $userid, $userid);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'File not found or access denied']);
        exit();
    }

    $file = $result->fetch_assoc();
    $extension = strtolower(pathinfo($file['filename'], PATHINFO_EXTENSION));
    
    // Always treat as text file (bypass binary detection)
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'filename' => $file['filename'],
        'file_type' => $file['file_type'],
        'content' => $file['content'],
        'extension' => $extension
    ]);
} else {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Invalid file ID']);
}
?>
