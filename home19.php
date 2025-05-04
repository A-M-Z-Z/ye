<?php
session_start();

// Verify user is logged in
if (!isset($_SESSION['username']) || !isset($_SESSION['user_id'])) {
    header("Location: expired");
    exit();
}
// Au début de la section de suppression de fichier
if (isset($_GET['delete_id']) && is_numeric($_GET['delete_id'])) {
    $file_id = intval($_GET['delete_id']);
    
    // Ajouter un message de débogage
    error_log("Tentative de suppression du fichier ID: $file_id");
    
    // Reste du code de suppression...
}

// Database Connection
$host = 'localhost';
$user = 'root';
$pass = 'root';
$dbname = 'cloudbox';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$username = $_SESSION['username'];
$userid = $_SESSION['user_id'];
$messages = [];

// Preview file content
function previewFile($fileId, $conn, $userId) {
    // Récupérer les informations du fichier
    $stmt = $conn->prepare("SELECT f.filename, f.file_type, fc.content 
                        FROM files f 
                        JOIN file_content fc ON f.id = fc.file_id 
                        WHERE f.id = ? AND (f.user_id = ? OR f.id IN (SELECT file_id FROM shared_files WHERE shared_with = ?))");
    $stmt->bind_param("iii", $fileId, $userId, $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        return ['success' => false, 'message' => 'File not found or access denied'];
    }

    $file = $result->fetch_assoc();
    
    // Obtenir l'extension du fichier
    $extension = strtolower(pathinfo($file['filename'], PATHINFO_EXTENSION));
    
    // Liste des types de fichiers binaires qui ne peuvent pas être prévisualisés
    $binaryTypes = [
        'image/', 'video/', 'audio/', 
        'application/zip', 'application/x-rar', 'application/x-compressed',
        'application/x-gzip', 'application/x-bzip2', 'application/pdf'
    ];
    
    // Types de fichiers que nous savons être du texte
    $textExtensions = [
        'txt', 'php', 'html', 'htm', 'css', 'js', 'json', 'xml', 
        'md', 'py', 'c', 'cpp', 'h', 'java', 'rb', 'go', 
        'sh', 'bat', 'ps1', 'sql', 'csv', 'log', 'conf',
        'ini', 'yml', 'yaml', 'toml', 'gitignore', 'htaccess'
    ];
    
    // Vérifier si c'est un fichier binaire connu
    $isBinary = false;
    
    // Si c'est une extension connue de fichier texte, on le traite comme tel
    if (in_array($extension, $textExtensions)) {
        $isBinary = false;
    } else {
        // Sinon, vérifier par le type MIME
        foreach ($binaryTypes as $type) {
            if (strpos($file['file_type'], $type) === 0) {
                $isBinary = true;
                break;
            }
        }
        
        // Cas spécial : PHP peut être application/octet-stream
        if ($isBinary && $file['file_type'] === 'application/octet-stream' && $extension === 'php') {
            $isBinary = false;
        }
        
        // Si le type commence par "text/", ce n'est pas binaire
        if (strpos($file['file_type'], 'text/') === 0) {
            $isBinary = false;
        }
    }
    
    // Forcer la prévisualisation si demandé
    if (isset($_GET['force_preview']) && $_GET['force_preview'] == 1) {
        $isBinary = false;
    }
    
    if ($isBinary) {
        return [
            'success' => false, 
            'message' => 'This file type cannot be previewed',
            'file_type' => $file['file_type'],
            'extension' => $extension,
            'filename' => $file['filename']
        ];
    }

    // Limiter la taille du contenu prévisualisé
    $maxPreviewSize = 100 * 1024; // 100 KB
    $content = $file['content'];
    $isTruncated = false;

    if (strlen($content) > $maxPreviewSize) {
        $content = substr($content, 0, $maxPreviewSize);
        $isTruncated = true;
    }

    // Ajouter un message si le contenu a été tronqué
    if ($isTruncated) {
        $content .= "\n\n[File content truncated. Download the full file to view the complete content.]";
    }

    return [
        'success' => true,
        'filename' => $file['filename'],
        'file_type' => $file['file_type'],
        'content' => $content,
        'extension' => $extension,
        'truncated' => $isTruncated
    ];
}

// Traiter la demande de prévisualisation si c'est une requête AJAX
if (isset($_GET['preview_id']) && is_numeric($_GET['preview_id'])) {
    $previewId = intval($_GET['preview_id']);
    $previewData = previewFile($previewId, $conn, $userid);
    
    header('Content-Type: application/json');
    echo json_encode($previewData);
    exit();
}

// Recherche de fichiers et dossiers
if (isset($_GET['search']) && !empty($_GET['search'])) {
    $searchTerm = '%' . $conn->real_escape_string($_GET['search']) . '%';
    $searchResults = [];

    // Recherche dans les fichiers
    $fileQuery = $conn->prepare("SELECT id, filename, file_size, file_type, folder_id, 'file' as type 
                               FROM files 
                               WHERE user_id = ? 
                               AND filename LIKE ? 
                               UNION
                               SELECT f.id, f.filename, f.file_size, f.file_type, f.folder_id, 'shared_file' as type
                               FROM files f
                               JOIN shared_files sf ON f.id = sf.file_id
                               WHERE sf.shared_with = ? AND f.filename LIKE ?");
    $fileQuery->bind_param("isis", $userid, $searchTerm, $userid, $searchTerm);
    $fileQuery->execute();
    $fileResult = $fileQuery->get_result();
    
    while ($file = $fileResult->fetch_assoc()) {
        $searchResults[] = $file;
    }

    // Recherche dans les dossiers
    $folderQuery = $conn->prepare("SELECT id, folder_name, parent_folder_id, 'folder' as type 
                                 FROM folders 
                                 WHERE user_id = ? 
                                 AND folder_name LIKE ?");
    $folderQuery->bind_param("is", $userid, $searchTerm);
    $folderQuery->execute();
    $folderResult = $folderQuery->get_result();
    
    while ($folder = $folderResult->fetch_assoc()) {
        $searchResults[] = $folder;
    }

    // Si c'est une requête AJAX pour la recherche
    if (isset($_GET['ajax_search'])) {
        header('Content-Type: application/json');
        echo json_encode($searchResults);
        exit();
    }
}

// Calculate current storage usage
$storageQuery = $conn->prepare("SELECT SUM(file_size) as total_used FROM files WHERE user_id = ?");
$storageQuery->bind_param("i", $userid);
$storageQuery->execute();
$result = $storageQuery->get_result();
$row = $result->fetch_assoc();
$currentUsage = $row['total_used'] ?: 0;

// Get user's quota
$quotaQuery = $conn->prepare("SELECT storage_quota FROM users WHERE id = ?");
$quotaQuery->bind_param("i", $userid);
$quotaQuery->execute();
$quotaResult = $quotaQuery->get_result();
$quotaRow = $quotaResult->fetch_assoc();
$userQuota = $quotaRow['storage_quota'] ?: 104857600; // Default 100MB

// Current folder ID
$current_folder_id = isset($_GET['folder_id']) ? intval($_GET['folder_id']) : null;

// Create folder
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_folder_name'])) {
    $folder_name = $conn->real_escape_string(trim($_POST['new_folder_name']));
    
    if (!empty($folder_name)) {
        // Create folder
        $query = "INSERT INTO folders (user_id, folder_name, parent_folder_id) VALUES ($userid, '$folder_name', ";
        $query .= $current_folder_id ? $current_folder_id : "NULL";
        $query .= ")";
        
        if ($conn->query($query)) {
            $messages[] = "<div class='alert alert-success'>Folder created successfully.</div>";
        } else {
            $messages[] = "<div class='alert alert-danger'>Error creating folder: " . $conn->error . "</div>";
        }
    }
}

// Share file with user
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['share_file_id']) && isset($_POST['share_username']) && isset($_POST['permission'])) {
    $fileId = intval($_POST['share_file_id']);
    $shareUsername = $conn->real_escape_string(trim($_POST['share_username']));
    $permission = $conn->real_escape_string(trim($_POST['permission']));
    $expirationDate = !empty($_POST['expiration_date']) ? $conn->real_escape_string(trim($_POST['expiration_date'])) : null;
    
    // Verify file exists and belongs to current user
    $fileCheck = $conn->prepare("SELECT id FROM files WHERE id = ? AND user_id = ?");
    $fileCheck->bind_param("ii", $fileId, $userid);
    $fileCheck->execute();
    if ($fileCheck->get_result()->num_rows > 0) {
        // Find the target user
        $userCheck = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $userCheck->bind_param("s", $shareUsername);
        $userCheck->execute();
        $userResult = $userCheck->get_result();
        
        if ($userResult->num_rows > 0) {
            $targetUser = $userResult->fetch_assoc();
            $targetUserId = $targetUser['id'];
            
            // Don't share with self
            if ($targetUserId != $userid) {
                // Check if already shared
                $shareCheck = $conn->prepare("SELECT id FROM shared_files WHERE file_id = ? AND shared_with = ?");
                $shareCheck->bind_param("ii", $fileId, $targetUserId);
                $shareCheck->execute();
                
                if ($shareCheck->get_result()->num_rows == 0) {
                    // Share the file
                    if ($expirationDate) {
                        $shareInsert = $conn->prepare("INSERT INTO shared_files (file_id, shared_by, shared_with, permission, share_date, expiration_date) 
                                                    VALUES (?, ?, ?, ?, NOW(), ?)");
                        $shareInsert->bind_param("iiiss", $fileId, $userid, $targetUserId, $permission, $expirationDate);
                    } else {
                        $shareInsert = $conn->prepare("INSERT INTO shared_files (file_id, shared_by, shared_with, permission, share_date) 
                                                    VALUES (?, ?, ?, ?, NOW())");
                        $shareInsert->bind_param("iiis", $fileId, $userid, $targetUserId, $permission);
                    }
                    
                    if ($shareInsert->execute()) {
                        $messages[] = "<div class='alert alert-success'>File shared successfully with $shareUsername.</div>";
                    } else {
                        $messages[] = "<div class='alert alert-danger'>Error sharing file: " . $conn->error . "</div>";
                    }
                } else {
                    // Update existing share
                    if ($expirationDate) {
                        $shareUpdate = $conn->prepare("UPDATE shared_files SET permission = ?, expiration_date = ? 
                                                     WHERE file_id = ? AND shared_with = ?");
                        $shareUpdate->bind_param("ssii", $permission, $expirationDate, $fileId, $targetUserId);
                    } else {
                        $shareUpdate = $conn->prepare("UPDATE shared_files SET permission = ?, expiration_date = NULL 
                                                     WHERE file_id = ? AND shared_with = ?");
                        $shareUpdate->bind_param("sii", $permission, $fileId, $targetUserId);
                    }
                    
                    if ($shareUpdate->execute()) {
                        $messages[] = "<div class='alert alert-success'>File sharing updated successfully with $shareUsername.</div>";
                    } else {
                        $messages[] = "<div class='alert alert-danger'>Error updating file sharing: " . $conn->error . "</div>";
                    }
                }
            } else {
                $messages[] = "<div class='alert alert-warning'>You cannot share a file with yourself.</div>";
            }
        } else {
            $messages[] = "<div class='alert alert-danger'>User '$shareUsername' not found.</div>";
        }
    } else {
        $messages[] = "<div class='alert alert-danger'>File not found or you don't have permission to share it.</div>";
    }
}

// Upload multiple files
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['files']) && !empty($_FILES['files']['name'][0])) {
    $uploadedFiles = $_FILES['files'];
    $fileCount = count($uploadedFiles['name']);
    $success = 0;
    $errors = 0;
    
    // Process each file
    for ($i = 0; $i < $fileCount; $i++) {
        if ($uploadedFiles['error'][$i] != 0) {
            $errors++;
            continue;
        }
        
        $fileName = $conn->real_escape_string($uploadedFiles['name'][$i]);
        $fileSize = $uploadedFiles['size'][$i];
        $fileTmpPath = $uploadedFiles['tmp_name'][$i];
        $fileType = $conn->real_escape_string($uploadedFiles['type'][$i]);
        
        // Check if this file would exceed quota
        if (($currentUsage + $fileSize) > $userQuota) {
            $errors++;
            $messages[] = "<div class='alert alert-danger'>Cannot upload file '{$fileName}': Storage quota exceeded. Your quota is " . 
                number_format($userQuota / 1048576, 2) . " MB and you're using " . 
                number_format($currentUsage / 1048576, 2) . " MB.</div>";
            continue; // Skip this file
        }
        
        // Check if file already exists
        $check_query = "SELECT id FROM files WHERE user_id = $userid AND filename = '$fileName'";
        if ($current_folder_id) {
            $check_query .= " AND folder_id = $current_folder_id";
        } else {
            $check_query .= " AND folder_id IS NULL";
        }
        
        $check = $conn->query($check_query);
        
        if ($check->num_rows > 0) {
            $errors++;
            $messages[] = "<div class='alert alert-danger'>File '{$fileName}' already exists in this location.</div>";
            continue;
        }
        
        // Read file content
        $file_content = file_get_contents($fileTmpPath);
        
        // Insert file metadata
        $insert_query = "INSERT INTO files (user_id, filename, file_size, file_type";
        $insert_query .= ", folder_id) VALUES ($userid, '$fileName', $fileSize, '$fileType'";
        $insert_query .= ", " . ($current_folder_id ? $current_folder_id : "NULL") . ")";
        
        if ($conn->query($insert_query)) {
            $file_id = $conn->insert_id;
            
            // Insert file content
            $content_insert = $conn->query("INSERT INTO file_content (file_id, content) VALUES ($file_id, '" . $conn->real_escape_string($file_content) . "')");
            
            if ($content_insert) {
                $success++;
                $currentUsage += $fileSize; // Update usage for next file check
            } else {
                $errors++;
                $messages[] = "<div class='alert alert-danger'>Error saving content for file '{$fileName}'.</div>";
            }
        } else {
            $errors++;
            $messages[] = "<div class='alert alert-danger'>Error saving metadata for file '{$fileName}'.</div>";
        }
    }
    
    if ($success > 0) {
        $messages[] = "<div class='alert alert-success'>Successfully uploaded $success files.</div>";
    }
    if ($errors > 0) {
        $messages[] = "<div class='alert alert-danger'>Failed to upload $errors files.</div>";
    }
}

// Delete folder
if (isset($_GET['delete_folder']) && is_numeric($_GET['delete_folder'])) {
    $folder_id = intval($_GET['delete_folder']);
    
    // Check if folder belongs to user
    $check = $conn->query("SELECT id FROM folders WHERE id = $folder_id AND user_id = $userid");
    if ($check->num_rows > 0) {
        if ($conn->query("DELETE FROM folders WHERE id = $folder_id")) {
            $messages[] = "<div class='alert alert-success'>Folder deleted successfully.</div>";
            
            // Redirect if current folder was deleted
            if ($folder_id == $current_folder_id) {
                $parent = $conn->query("SELECT parent_folder_id FROM folders WHERE id = $folder_id")->fetch_assoc();
                $parent_id = $parent ? $parent['parent_folder_id'] : null;
                
                header("Location: home.php" . ($parent_id ? "?folder_id=$parent_id" : ""));
                exit();
            }
        } else {
            $messages[] = "<div class='alert alert-danger'>Error deleting folder: " . $conn->error . "</div>";
        }
    }
}

// Delete file
if (isset($_GET['delete_id']) && is_numeric($_GET['delete_id'])) {
    $file_id = intval($_GET['delete_id']);
    
    // Obtenir la taille du fichier avant la suppression
    $sizeQuery = $conn->prepare("SELECT file_size FROM files WHERE id = ? AND user_id = ?");
    $sizeQuery->bind_param("ii", $file_id, $userid);
    $sizeQuery->execute();
    $sizeResult = $sizeQuery->get_result();
    $fileSize = 0;
    
    if ($sizeResult->num_rows > 0) {
        $sizeRow = $sizeResult->fetch_assoc();
        $fileSize = $sizeRow['file_size'];
    }
    
    // Vérifier si le fichier appartient à l'utilisateur
    $checkQuery = $conn->prepare("SELECT id FROM files WHERE id = ? AND user_id = ?");
    $checkQuery->bind_param("ii", $file_id, $userid);
    $checkQuery->execute();
    $result = $checkQuery->get_result();
    
    if ($result->num_rows > 0) {
        // Commencer une transaction
        $conn->begin_transaction();
        
        try {
            // Supprimer les entrées de partage
            $shareQuery = $conn->prepare("DELETE FROM shared_files WHERE file_id = ?");
            $shareQuery->bind_param("i", $file_id);
            $shareQuery->execute();
            
            // Supprimer le contenu du fichier
            $contentQuery = $conn->prepare("DELETE FROM file_content WHERE file_id = ?");
            $contentQuery->bind_param("i", $file_id);
            $contentQuery->execute();
            
            // Supprimer le fichier
            $fileQuery = $conn->prepare("DELETE FROM files WHERE id = ? AND user_id = ?");
            $fileQuery->bind_param("ii", $file_id, $userid);
            $fileQuery->execute();
            
            // Valider les changements
            $conn->commit();
            
            $messages[] = "<div class='alert alert-success'>File deleted successfully.</div>";
            
            // Mettre à jour l'utilisation actuelle après la suppression
            if ($fileSize > 0) {
                $currentUsage = max(0, $currentUsage - $fileSize);
            }
        } catch (Exception $e) {
            // Annuler les changements en cas d'erreur
            $conn->rollback();
            $messages[] = "<div class='alert alert-danger'>Error deleting file: " . $e->getMessage() . "</div>";
        }
    } else {
        $messages[] = "<div class='alert alert-danger'>File not found or you don't have permission to delete it.</div>";
    }
}

// Stop sharing a file
if (isset($_GET['stop_sharing']) && is_numeric($_GET['stop_sharing']) && isset($_GET['user_id']) && is_numeric($_GET['user_id'])) {
    $file_id = intval($_GET['stop_sharing']);
    $target_user_id = intval($_GET['user_id']);
    
    // Check if file belongs to user
    $check = $conn->query("SELECT id FROM files WHERE id = $file_id AND user_id = $userid");
    if ($check->num_rows > 0) {
        if ($conn->query("DELETE FROM shared_files WHERE file_id = $file_id AND shared_with = $target_user_id")) {
            $messages[] = "<div class='alert alert-success'>File sharing stopped successfully.</div>";
        } else {
            $messages[] = "<div class='alert alert-danger'>Error stopping file sharing: " . $conn->error . "</div>";
        }
    }
}

// Get current folder info
$current_folder_name = "Root";
$parent_folder_id = null;

if ($current_folder_id) {
    $folder_info = $conn->query("SELECT folder_name, parent_folder_id FROM folders WHERE id = $current_folder_id AND user_id = $userid");
    if ($folder_info->num_rows > 0) {
        $folder = $folder_info->fetch_assoc();
        $current_folder_name = $folder['folder_name'];
        $parent_folder_id = $folder['parent_folder_id'];
    } else {
        // Invalid folder ID, redirect to root
        header("Location: home.php");
        exit();
    }
}

// Get subfolders
$folders = [];
$query = "SELECT id, folder_name FROM folders WHERE user_id = $userid AND ";
$query .= $current_folder_id ? "parent_folder_id = $current_folder_id" : "parent_folder_id IS NULL";
$query .= " ORDER BY folder_name";

$result = $conn->query($query);
while ($folder = $result->fetch_assoc()) {
    $folders[] = $folder;
}

// Get files in current folder
$files = [];
$query = "SELECT id, filename, file_size, file_type FROM files WHERE user_id = $userid AND ";
$query .= $current_folder_id ? "folder_id = $current_folder_id" : "folder_id IS NULL";
$query .= " ORDER BY filename";

$result = $conn->query($query);
while ($file = $result->fetch_assoc()) {
    // Get sharing info for this file
    $shareQuery = $conn->prepare("SELECT sf.shared_with, sf.permission, sf.expiration_date, u.username 
                                FROM shared_files sf 
                                JOIN users u ON sf.shared_with = u.id 
                                WHERE sf.file_id = ?");
    $shareQuery->bind_param("i", $file['id']);
    $shareQuery->execute();
    $shareResult = $shareQuery->get_result();
    
    $shares = [];
    while ($share = $shareResult->fetch_assoc()) {
        $shares[] = $share;
    }
    
    $file['shares'] = $shares;
    $files[] = $file;
}

// Get shared files with current user
$shared_files = [];
$sharedQuery = $conn->prepare("SELECT f.id, f.filename, f.file_size, f.file_type, sf.permission, 
                             sf.expiration_date, u.username as shared_by
                             FROM files f
                             JOIN shared_files sf ON f.id = sf.file_id
                             JOIN users u ON f.user_id = u.id
                             WHERE sf.shared_with = ?
                             ORDER BY f.filename");
$sharedQuery->bind_param("i", $userid);
$sharedQuery->execute();
$sharedResult = $sharedQuery->get_result();

while ($file = $sharedResult->fetch_assoc()) {
    $shared_files[] = $file;
}

// Get breadcrumb
function getBreadcrumb($conn, $folder_id, $userid) {
    $path = [];
    $current = $folder_id;
    
    while ($current) {
        $result = $conn->query("SELECT id, folder_name, parent_folder_id FROM folders WHERE id = $current AND user_id = $userid");
        if ($result->num_rows > 0) {
            $folder = $result->fetch_assoc();
            array_unshift($path, ['id' => $folder['id'], 'name' => $folder['folder_name']]);
            $current = $folder['parent_folder_id'];
        } else {
            break;
        }
    }
    
    return $path;
}

$breadcrumb = $current_folder_id ? getBreadcrumb($conn, $current_folder_id, $userid) : [];

// Calculate usage percentage for the storage bar
$usagePercentage = ($userQuota > 0) ? ($currentUsage / $userQuota) * 100 : 0;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudBOX - Files and Folders</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Flatpickr for date selection -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <!-- Prism.js pour la coloration syntaxique -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <!-- Prism components for languages -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-php.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-css.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-markup.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-c.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-cpp.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-java.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-sql.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/docx-preview@0.1.15/dist/docx-preview.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/web/pdf_viewer.min.css">
    <script src="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/javascript/javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/htmlmixed/htmlmixed.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/xml/xml.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/css/css.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/php/php.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/python/python.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/clike/clike.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/shell/shell.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/sql/sql.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/edit/matchbrackets.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/edit/closebrackets.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/comment/comment.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/selection/active-line.min.js"></script>
<script>// Variable to store CodeMirror editor
let editor = null;
let currentEditingFileId = null;
let currentFontSize = 14;
let saveTimeout = null;
let lastSavedContent = "";
let isEditorDirty = false;

// Function to edit a file
function editFile(fileId) {
    currentEditingFileId = fileId;
    const editorStatus = document.getElementById('editorStatus');
    editorStatus.textContent = 'Loading...';
    
    // Clear previous editor if it exists
    if (editor) {
        editor.toTextArea();
        editor = null;
    }
    
    // Show the edit modal
    const editModal = new bootstrap.Modal(document.getElementById('editModal'));
    editModal.show();
    
    // Use our direct edit endpoint instead of the preview endpoint
    fetch(`direct_edit.php?file_id=${fileId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update modal title
                document.getElementById('editModalLabel').textContent = `Edit: ${data.filename}`;
                
                // Set editor content
                const textarea = document.getElementById('fileEditor');
                textarea.value = data.content;
                lastSavedContent = data.content;
                
                // Initialize CodeMirror with appropriate mode
                const extension = data.extension.toLowerCase();
                let mode = 'text/plain';
                
                // Map file extensions to CodeMirror modes
                const modeMap = {
                    'js': 'text/javascript',
                    'html': 'text/html',
                    'htm': 'text/html',
                    'css': 'text/css',
                    'php': 'application/x-httpd-php',
                    'py': 'text/x-python',
                    'java': 'text/x-java',
                    'c': 'text/x-csrc',
                    'cpp': 'text/x-c++src',
                    'h': 'text/x-csrc',
                    'rb': 'text/x-ruby',
                    'sql': 'text/x-sql',
                    'sh': 'text/x-sh',
                    'xml': 'application/xml',
                    'json': 'application/json',
                    'txt': 'text/plain',
                    'md': 'text/markdown'
                };
                
                if (modeMap[extension]) {
                    mode = modeMap[extension];
                }
                
                // Initialize CodeMirror
                editor = CodeMirror.fromTextArea(textarea, {
                    lineNumbers: true,
                    indentUnit: 4,
                    mode: mode,
                    theme: 'default',
                    matchBrackets: true,
                    autoCloseBrackets: true,
                    styleActiveLine: true,
                    lineWrapping: true,
                    tabSize: 4,
                    indentWithTabs: false,
                    extraKeys: {
                        "Ctrl-S": function(cm) {
                            saveFile();
                            return false;
                        },
                        "Cmd-S": function(cm) {
                            saveFile();
                            return false;
                        }
                    }
                });
                
                // Set font size
                editor.getWrapperElement().style.fontSize = `${currentFontSize}px`;
                
                // Set up change tracking
                editor.on('change', function() {
                    isEditorDirty = editor.getValue() !== lastSavedContent;
                    editorStatus.textContent = isEditorDirty ? 'Unsaved changes' : 'Saved';
                    
                    // Auto-save after 3 seconds of inactivity
                    if (saveTimeout) {
                        clearTimeout(saveTimeout);
                    }
                    
                    if (isEditorDirty) {
                        saveTimeout = setTimeout(function() {
                            saveFile(true); // Silent save
                        }, 3000);
                    }
                });
                
                // Force a refresh to ensure proper rendering
                setTimeout(() => {
                    editor.refresh();
                    editorStatus.textContent = 'Ready';
                }, 100);
            } else {
                editorStatus.textContent = 'Error loading file';
                alert('Error loading file: ' + data.message);
            }
        })
        .catch(error => {
            editorStatus.textContent = 'Error loading file';
            alert('An error occurred while loading the file.');
            console.error('Error:', error);
        });
}

// Function to save edited file
function saveFile(silent = false) {
    if (!currentEditingFileId || !editor) return;
    
    // Get content from editor
    const content = editor.getValue();
    
    // If content hasn't changed, don't save
    if (content === lastSavedContent) {
        if (!silent) {
            showNotification('No changes to save', 'info');
        }
        return;
    }
    
    // Create form data
    const formData = new FormData();
    formData.append('file_id', currentEditingFileId);
    formData.append('content', content);
    
    // Update status
    const editorStatus = document.getElementById('editorStatus');
    editorStatus.textContent = 'Saving...';
    
    // Show saving indicator if not silent
    if (!silent) {
        const saveBtn = document.getElementById('saveFileBtn');
        const originalHTML = saveBtn.innerHTML;
        saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Saving...';
        saveBtn.disabled = true;
    }
    
    // Send the request
    fetch('update_file.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            lastSavedContent = content;
            isEditorDirty = false;
            editorStatus.textContent = 'Saved at ' + new Date().toLocaleTimeString();
            
            if (!silent) {
                // Show success notification
                showNotification('File saved successfully', 'success');
                
                // Reset save button
                const saveBtn = document.getElementById('saveFileBtn');
                saveBtn.innerHTML = '<i class="fas fa-save me-1"></i> Save';
                saveBtn.disabled = false;
            }
        } else {
            editorStatus.textContent = 'Error saving';
            
            if (!silent) {
                // Show error notification
                showNotification('Error saving file: ' + data.message, 'error');
                
                // Reset save button
                const saveBtn = document.getElementById('saveFileBtn');
                saveBtn.innerHTML = '<i class="fas fa-save me-1"></i> Save';
                saveBtn.disabled = false;
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        editorStatus.textContent = 'Error saving';
        
        if (!silent) {
            // Show error notification
            showNotification('Error saving file', 'error');
            
            // Reset save button
            const saveBtn = document.getElementById('saveFileBtn');
            saveBtn.innerHTML = '<i class="fas fa-save me-1"></i> Save';
            saveBtn.disabled = false;
        }
    });
}

// Function to show notifications
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `drag-message ${type === 'success' ? 'success-message' : type === 'info' ? 'info-message' : 'error-message'}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    // Remove notification after delay
    setTimeout(() => {
        notification.remove();
    }, 2000);
}

// Add event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Save button click
    const saveFileBtn = document.getElementById('saveFileBtn');
    if (saveFileBtn) {
        saveFileBtn.addEventListener('click', () => saveFile());
    }
    
    // Save and close button click
    const saveCloseBtn = document.getElementById('saveCloseBtn');
    if (saveCloseBtn) {
        saveCloseBtn.addEventListener('click', function() {
            saveFile();
            setTimeout(() => {
                bootstrap.Modal.getInstance(document.getElementById('editModal')).hide();
                
                // Refresh preview if it's open
                if (document.getElementById('previewModal').classList.contains('show')) {
                    previewFile(currentEditingFileId, true);
                }
            }, 500);
        });
    }
    
    // Undo and redo buttons
    const undoBtn = document.getElementById('undoBtn');
    const redoBtn = document.getElementById('redoBtn');
    if (undoBtn && redoBtn) {
        undoBtn.addEventListener('click', function() {
            if (editor) editor.undo();
        });
        
        redoBtn.addEventListener('click', function() {
            if (editor) editor.redo();
        });
    }
    
    // Font size buttons
    const increaseFontBtn = document.getElementById('increaseFontBtn');
    const decreaseFontBtn = document.getElementById('decreaseFontBtn');
    if (increaseFontBtn && decreaseFontBtn) {
        increaseFontBtn.addEventListener('click', function() {
            if (editor) {
                currentFontSize = Math.min(currentFontSize + 2, 32);
                editor.getWrapperElement().style.fontSize = `${currentFontSize}px`;
                editor.refresh();
            }
        });
        
        decreaseFontBtn.addEventListener('click', function() {
            if (editor) {
                currentFontSize = Math.max(currentFontSize - 2, 10);
                editor.getWrapperElement().style.fontSize = `${currentFontSize}px`;
                editor.refresh();
            }
        });
    }
    
    // Warn about unsaved changes
    window.addEventListener('beforeunload', function(e) {
        if (isEditorDirty) {
            e.preventDefault();
            e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            return e.returnValue;
        }
    });
    
    // Handle edit modal close
    document.getElementById('editModal').addEventListener('hide.bs.modal', function(e) {
        if (isEditorDirty) {
            const confirmLeave = confirm('You have unsaved changes. Do you want to save before closing?');
            if (confirmLeave) {
                e.preventDefault();
                saveFile();
                setTimeout(() => {
                    bootstrap.Modal.getInstance(document.getElementById('editModal')).hide();
                }, 500);
            }
        }
        
        // Cleanup
        if (saveTimeout) {
            clearTimeout(saveTimeout);
            saveTimeout = null;
        }
    });
}); </script>
    <script>
function searchItems() {
    // Get the search text
    const searchText = document.getElementById('searchInput').value.toLowerCase();
    
    // If empty, show everything
    if (searchText.trim() === '') {
        document.querySelectorAll('.item').forEach(item => {
            item.style.display = 'flex';
        });
        return;
    }
    
    // Filter items
    document.querySelectorAll('.item').forEach(item => {
        const nameElement = item.querySelector('.name');
        if (nameElement) {
            const itemName = nameElement.textContent.toLowerCase();
            if (itemName.includes(searchText)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        }
    });
}

// Wait for DOM to be fully loaded then add event listener
document.addEventListener('DOMContentLoaded', function() {
    // Add event listener to search input
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', searchItems);
    }
});
</script>
    <script> function previewFile(fileId, forcePreview = false) {
    const modal = new bootstrap.Modal(document.getElementById('previewModal'));
    const previewLoader = document.getElementById('previewLoader');
    const fileContent = document.getElementById('fileContent');
    const codeContent = document.getElementById('codeContent');
    const downloadBtn = document.getElementById('downloadPreviewBtn');
    const modalTitle = document.getElementById('previewModalLabel');
    const debugInfo = document.getElementById('debug-info');
    
    // Create preview container for non-text files (if it doesn't exist yet)
    let mediaPreviewContainer = document.getElementById('mediaPreviewContainer');
    if (!mediaPreviewContainer) {
        mediaPreviewContainer = document.createElement('div');
        mediaPreviewContainer.id = 'mediaPreviewContainer';
        mediaPreviewContainer.className = 'media-preview-container';
        fileContent.parentNode.insertBefore(mediaPreviewContainer, fileContent);
    }
    
    // Reset all preview containers
    fileContent.style.display = 'none';
    mediaPreviewContainer.style.display = 'none';
    mediaPreviewContainer.innerHTML = '';
    previewLoader.style.display = 'block';
    debugInfo.style.display = 'none';
    codeContent.textContent = '';
    codeContent.className = 'language-none';
    downloadBtn.href = `download.php?id=${fileId}`;
    
    // Show the modal
    modal.show();
    
    // Prepare the request URL
    let url = `home.php?preview_id=${fileId}`;
    if (forcePreview) {
        url += '&force_preview=1';
    }
    
    // First, get the file metadata to determine file type
    fetch(`get_file_info.php?file_id=${fileId}`)
        .then(response => response.json())
        .then(fileInfo => {
            if (!fileInfo.success) {
                throw new Error(fileInfo.message || 'Failed to get file information');
            }
            
            modalTitle.textContent = `Preview: ${fileInfo.filename}`;
            debugInfo.innerHTML = `<strong>File Type:</strong> ${fileInfo.file_type}<br><strong>Extension:</strong> ${fileInfo.extension || 'N/A'}`;
            debugInfo.style.display = 'block';
            
            const fileType = fileInfo.file_type;
            const extension = fileInfo.extension.toLowerCase();
            
            // Handle different file types
            if (fileType.startsWith('image/')) {
                // Image preview
                previewImage(fileId, mediaPreviewContainer);
            } else if (fileType === 'application/pdf' || extension === 'pdf') {
                // PDF preview
                previewPDF(fileId, mediaPreviewContainer);
            } else if (extension === 'docx' || fileType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                // Word document preview
                previewDOCX(fileId, mediaPreviewContainer);
            } else {
                // Text-based preview (use existing code logic)
                fetch(url)
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Determine language for syntax highlighting
                            let language = 'none';
                            const languageMap = {
                                'html': 'markup',
                                'htm': 'markup',
                                'xml': 'markup',
                                'css': 'css',
                                'js': 'javascript',
                                'json': 'json',
                                'php': 'php',
                                'py': 'python',
                                'c': 'c',
                                'cpp': 'cpp',
                                'h': 'c',
                                'java': 'java',
                                'sh': 'bash',
                                'bat': 'batch',
                                'ps1': 'powershell',
                                'sql': 'sql',
                                'rb': 'ruby',
                                'go': 'go'
                            };
                            
                            if (languageMap[extension]) {
                                language = languageMap[extension];
                            } else if (fileType.includes('text/html')) {
                                language = 'markup';
                            } else if (fileType.includes('text/css')) {
                                language = 'css';
                            } else if (fileType.includes('application/javascript')) {
                                language = 'javascript';
                            } else if (fileType.includes('application/json')) {
                                language = 'json';
                            } else if (fileType.includes('text/x-python') || extension === 'py') {
                                language = 'python';
                            } else if (fileType.includes('text/x-php') || 
                                      (fileType.includes('application/octet-stream') && extension === 'php') || 
                                      extension === 'php') {
                                language = 'php';
                            } else if (fileType.includes('text/plain')) {
                                language = 'none';
                            }
                            
                            // Update language class and content
                            codeContent.className = `language-${language}`;
                            codeContent.textContent = data.content;
                            
                            // Apply syntax highlighting
                            Prism.highlightElement(codeContent);
                            
                            // Show the content
                            previewLoader.style.display = 'none';
                            fileContent.style.display = 'block';
                        } else {
                            // Show error message
                            codeContent.textContent = 'Error loading file: ' + data.message;
                            fileContent.style.display = 'block';
                            previewLoader.style.display = 'none';
                        }
                    })
                    .catch(error => {
                        codeContent.textContent = 'An error occurred while loading the file.';
                        fileContent.style.display = 'block';
                        previewLoader.style.display = 'none';
                        console.error('Error:', error);
                    });
            }
        })
        .catch(error => {
            codeContent.textContent = 'An error occurred while loading the file: ' + error.message;
            fileContent.style.display = 'block';
            previewLoader.style.display = 'none';
            console.error('Error:', error);
        });
}

// Function to preview images
function previewImage(fileId, container) {
    container.innerHTML = '';
    
    // Create image element
    const img = document.createElement('img');
    img.classList.add('img-fluid', 'rounded', 'mx-auto', 'd-block');
    img.alt = 'Image Preview';
    img.style.maxHeight = '70vh';
    
    // Set image source to file download URL
    img.src = `get_file_content.php?file_id=${fileId}&raw=1`;
    
    // Add image controls
    const controls = document.createElement('div');
    controls.className = 'text-center mt-3';
    controls.innerHTML = `
        <button class="btn btn-sm btn-outline-secondary me-2" onclick="rotateImage(-90)">
            <i class="fas fa-undo"></i> Rotate Left
        </button>
        <button class="btn btn-sm btn-outline-secondary me-2" onclick="rotateImage(90)">
            <i class="fas fa-redo"></i> Rotate Right
        </button>
        <button class="btn btn-sm btn-outline-secondary me-2" onclick="zoomImage(1.2)">
            <i class="fas fa-search-plus"></i> Zoom In
        </button>
        <button class="btn btn-sm btn-outline-secondary me-2" onclick="zoomImage(0.8)">
            <i class="fas fa-search-minus"></i> Zoom Out
        </button>
        <button class="btn btn-sm btn-outline-secondary" onclick="resetImage()">
            <i class="fas fa-sync"></i> Reset
        </button>
    `;
    
    // Add image and controls to container
    container.appendChild(img);
    container.appendChild(controls);
    
    // Show the container and hide the loader
    container.style.display = 'block';
    document.getElementById('previewLoader').style.display = 'none';
    
    // Store the current rotation and zoom level
    container.dataset.rotation = '0';
    container.dataset.zoom = '1';
}

// Image manipulation functions
function rotateImage(degrees) {
    const container = document.getElementById('mediaPreviewContainer');
    const img = container.querySelector('img');
    
    if (img) {
        // Update stored rotation
        const currentRotation = parseInt(container.dataset.rotation || 0);
        const newRotation = currentRotation + degrees;
        container.dataset.rotation = newRotation.toString();
        
        // Apply rotation
        img.style.transform = `rotate(${newRotation}deg) scale(${container.dataset.zoom})`;
    }
}

function zoomImage(factor) {
    const container = document.getElementById('mediaPreviewContainer');
    const img = container.querySelector('img');
    
    if (img) {
        // Update stored zoom
        const currentZoom = parseFloat(container.dataset.zoom || 1);
        const newZoom = currentZoom * factor;
        container.dataset.zoom = newZoom.toString();
        
        // Apply zoom
        img.style.transform = `rotate(${container.dataset.rotation}deg) scale(${newZoom})`;
    }
}

function resetImage() {
    const container = document.getElementById('mediaPreviewContainer');
    const img = container.querySelector('img');
    
    if (img) {
        container.dataset.rotation = '0';
        container.dataset.zoom = '1';
        img.style.transform = '';
    }
}

// Function to preview PDF files
function previewPDF(fileId, container) {
    container.innerHTML = '';
    
    // Create PDF viewer container
    const pdfContainer = document.createElement('div');
    pdfContainer.className = 'pdf-container';
    pdfContainer.style.height = '70vh';
    pdfContainer.style.overflow = 'auto';
    pdfContainer.style.border = '1px solid #dee2e6';
    pdfContainer.style.borderRadius = '0.25rem';
    
    // Add the PDF container to the main container
    container.appendChild(pdfContainer);
    
    // Show the container and hide the loader
    container.style.display = 'block';
    
    // Get the file content URL
    const pdfUrl = `get_file_content.php?file_id=${fileId}&raw=1`;
    
    // Initialize PDF.js
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
    
    // Load and render the PDF
    pdfjsLib.getDocument(pdfUrl).promise.then(pdf => {
        // Create PDF viewer controls
        const controls = document.createElement('div');
        controls.className = 'text-center mb-3';
        controls.innerHTML = `
            <div class="btn-group">
                <button class="btn btn-sm btn-outline-secondary" id="prevPage" disabled>
                    <i class="fas fa-arrow-left"></i> Previous
                </button>
                <span class="btn btn-sm btn-outline-secondary" id="pageInfo">Page 1 of ${pdf.numPages}</span>
                <button class="btn btn-sm btn-outline-secondary" id="nextPage">
                    <i class="fas fa-arrow-right"></i> Next
                </button>
            </div>
            <div class="btn-group ms-2">
                <button class="btn btn-sm btn-outline-secondary" id="zoomOut">
                    <i class="fas fa-search-minus"></i>
                </button>
                <span class="btn btn-sm btn-outline-secondary" id="zoomLevel">100%</span>
                <button class="btn btn-sm btn-outline-secondary" id="zoomIn">
                    <i class="fas fa-search-plus"></i>
                </button>
            </div>
        `;
        
        container.insertBefore(controls, pdfContainer);
        
        // Set up viewer state
        let currentPage = 1;
        let currentZoom = 1.0;
        const pageInfo = document.getElementById('pageInfo');
        const prevButton = document.getElementById('prevPage');
        const nextButton = document.getElementById('nextPage');
        const zoomIn = document.getElementById('zoomIn');
        const zoomOut = document.getElementById('zoomOut');
        const zoomLevel = document.getElementById('zoomLevel');
        
        // Function to render a specific page
        function renderPage(pageNum) {
            pdf.getPage(pageNum).then(page => {
                const viewport = page.getViewport({ scale: currentZoom });
                
                // Clear previous content
                pdfContainer.innerHTML = '';
                
                // Create canvas for the page
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = viewport.width;
                canvas.height = viewport.height;
                
                // Render PDF page
                const renderContext = {
                    canvasContext: ctx,
                    viewport: viewport
                };
                
                page.render(renderContext).promise.then(() => {
                    pdfContainer.appendChild(canvas);
                    
                    // Update page info and controls
                    pageInfo.textContent = `Page ${pageNum} of ${pdf.numPages}`;
                    prevButton.disabled = pageNum <= 1;
                    nextButton.disabled = pageNum >= pdf.numPages;
                    
                    // Hide the loader
                    document.getElementById('previewLoader').style.display = 'none';
                });
            });
        }
        
        // Initial render
        renderPage(currentPage);
        
        // Add event listeners to buttons
        prevButton.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderPage(currentPage);
            }
        });
        
        nextButton.addEventListener('click', () => {
            if (currentPage < pdf.numPages) {
                currentPage++;
                renderPage(currentPage);
            }
        });
        
        zoomIn.addEventListener('click', () => {
            currentZoom *= 1.2;
            zoomLevel.textContent = `${Math.round(currentZoom * 100)}%`;
            renderPage(currentPage);
        });
        
        zoomOut.addEventListener('click', () => {
            currentZoom *= 0.8;
            zoomLevel.textContent = `${Math.round(currentZoom * 100)}%`;
            renderPage(currentPage);
        });
    }).catch(error => {
        container.innerHTML = `<div class="alert alert-danger">Failed to load PDF: ${error.message}</div>`;
        document.getElementById('previewLoader').style.display = 'none';
    });
}

// Function to preview DOCX files
function previewDOCX(fileId, container) {
    container.innerHTML = '';
    
    // Create DOCX viewer container
    const docxContainer = document.createElement('div');
    docxContainer.className = 'docx-container';
    docxContainer.style.height = '70vh';
    docxContainer.style.overflow = 'auto';
    docxContainer.style.border = '1px solid #dee2e6';
    docxContainer.style.borderRadius = '0.25rem';
    docxContainer.style.padding = '20px';
    docxContainer.style.backgroundColor = 'white';
    
    // Add the DOCX container to the main container
    container.appendChild(docxContainer);
    
    // Show the container and hide the loader
    container.style.display = 'block';
    
    // Get the file content URL
    const docxUrl = `get_file_content.php?file_id=${fileId}&raw=1`;
    
    // Fetch the file content
    fetch(docxUrl)
        .then(response => response.arrayBuffer())
        .then(buffer => {
            // Use docx-preview to render the document
            docx.renderAsync(buffer, docxContainer, null, {
                className: 'docx-rendered',
                inWrapper: true,
                ignoreWidth: true,
                ignoreHeight: true,
                useBase64URL: true
            }).then(() => {
                // Hide the loader once the document is rendered
                document.getElementById('previewLoader').style.display = 'none';
            }).catch(error => {
                container.innerHTML = `<div class="alert alert-danger">Failed to render DOCX file: ${error.message}</div>`;
                document.getElementById('previewLoader').style.display = 'none';
            });
        })
        .catch(error => {
            container.innerHTML = `<div class="alert alert-danger">Failed to load DOCX file: ${error.message}</div>`;
            document.getElementById('previewLoader').style.display = 'none';
        });
}</script>
    <!-- Custom CSS -->
    <link rel="stylesheet" href="style.css">
    <style>
/* Code editor styles */
.CodeMirror {
    height: 70vh;
    font-family: 'Fira Code', 'Courier New', monospace;
    font-size: 14px;
    border: 1px solid #ddd;
    border-radius: 4px;
}

.editor-toolbar {
    background-color: #f8f9fa;
    border-radius: 4px;
    padding: 8px;
}

.CodeMirror-focused {
    border-color: #4f46e5;
    box-shadow: 0 0 0 0.2rem rgba(79, 70, 229, 0.25);
}

/* Status notifications */
.status-notification {
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 10px 15px;
    border-radius: 4px;
    z-index: 1050;
    animation: fadeInOut 2.5s forwards;
    color: white;
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
}

.status-success {
    background-color: #10b981;
}

.status-error {
    background-color: #ef4444;
}

.status-info {
    background-color: #3b82f6;
}

@keyframes fadeInOut {
    0% { opacity: 0; transform: translateY(20px); }
    15% { opacity: 1; transform: translateY(0); }
    85% { opacity: 1; transform: translateY(0); }
    100% { opacity: 0; transform: translateY(-20px); }
}
</style>
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .top-bar {
            background-color: #4f46e5;
            padding: 15px;
            display: flex;
            align-items: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .logo {
            margin-right: 15px;
        }
        
        .top-bar h1 {
            margin: 0;
            font-size: 22px;
        }
        
        .search-bar {
            margin-left: auto;
        }
        
        .search-bar input {
            border-radius: 20px;
            padding: 8px 15px;
            border: none;
            width: 250px;
        }
        
        .dashboard-nav {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .dashboard-nav a {
            color: #4b5563;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 6px;
            transition: background-color 0.2s;
        }
        
        .dashboard-nav a:hover {
            background-color: #f3f4f6;
            color: #4f46e5;
        }
        
        main {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .container-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .item {
            background-color: #fff;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        
        .folder-icon {
            color: #4f46e5;
        }
        
        .file-icon {
            color: #60a5fa;
        }
        
        .shared-icon {
            color: #10b981;
            position: absolute;
            top: 15px;
            right: 15px;
            font-size: 18px;
        }
        
        .name {
            text-align: center;
            font-weight: 500;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            width: 100%;
            margin-bottom: 10px;
        }
        
        .actions {
            display: flex;
            margin-top: 10px;
            gap: 10px;
            width: 100%;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .file-details {
            font-size: 13px;
            color: #6b7280;
            text-align: center;
            margin-top: 5px;
        }
        
        .drag-area {
            border: 2px dashed #d1d5db;
            border-radius: 8px;
            padding: 30px 20px;
            text-align: center;
            transition: border-color 0.3s;
            margin-bottom: 15px;
            position: relative;
            cursor: pointer;
        }
        
        .drag-area.active {
            border-color: #4f46e5;
            background-color: rgba(79, 70, 229, 0.05);
        }
        
        .drag-area i {
            font-size: 48px;
            color: #9ca3af;
            margin-bottom: 15px;
        }
        
        .storage-card {
            background-color: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .storage-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .storage-title {
            font-size: 18px;
            font-weight: 600;
            margin: 0;
        }
        
        .storage-status {
            font-size: 14px;
            color: <?= $usagePercentage > 90 ? '#dc3545' : ($usagePercentage > 70 ? '#fd7e14' : '#198754') ?>;
            font-weight: 500;
        }
        
        .storage-progress-container {
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            margin-bottom: 10px;
            overflow: hidden;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .storage-progress {
            height: 100%;
            border-radius: 10px;
            background: <?= $usagePercentage > 90 ? 
                        'linear-gradient(90deg, #dc3545 0%, #f44336 100%)' : 
                        ($usagePercentage > 70 ? 
                            'linear-gradient(90deg, #fd7e14 0%, #ffb74d 100%)' : 
                            'linear-gradient(90deg, #198754 0%, #20c997 100%)') ?>;
            width: <?= min(100, $usagePercentage) ?>%;
            transition: width 1s ease;
            position: relative;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .storage-progress-text {
            position: absolute;
            color: <?= $usagePercentage > 50 ? 'white' : '#212529' ?>;
            font-weight: 600;
            font-size: 12px;
            text-shadow: 0 1px 1px rgba(0,0,0,0.2);
            width: 100%;
            text-align: center;
        }
        
        .storage-details {
            display: flex;
            justify-content: space-between;
            font-size: 14px;
            color: #6c757d;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .section-header i {
            font-size: 24px;
            margin-right: 10px;
            color: #4f46e5;
        }
        
        .section-title {
            font-size: 20px;
            font-weight: 600;
            margin: 0;
            color: #343a40;
        }
        
        .btn-action {
            padding: 6px 12px;
            font-size: 14px;
            border-radius: 6px;
        }
        
        /* Bootstrap adjustments */
        .card {
            border: none;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-radius: 10px;
        }
        
        .form-control {
            border-radius: 6px;
            padding: 10px 15px;
        }
        
        .btn-primary {
            background-color: #4f46e5;
            border-color: #4f46e5;
        }
        
        .btn-primary:hover {
            background-color: #4338ca;
            border-color: #4338ca;
        }
        
        .btn-success {
            background-color: #059669;
            border-color: #059669;
        }
        
        .btn-success:hover {
            background-color: #047857;
            border-color: #047857;
        }
        
        .btn-danger {
            background-color: #ef4444;
            border-color: #ef4444;
        }
        
        .btn-danger:hover {
            background-color: #dc2626;
            border-color: #dc2626;
        }
        
        /* Prism.js code preview adjustments */
        #fileContent {
            max-height: 500px;
            overflow: auto;
            padding: 1rem;
            border-radius: 0.375rem;
            background-color: #f8f9fa;
        }
        
        code[class*="language-"] {
            color: #000;
            font-size: 14px;
            line-height: 1.5;
            text-shadow: none;
        }
        
        pre[class*="language-"] {
            padding: 0;
            margin: 0;
            overflow: auto;
            border-radius: 0.375rem;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container-grid {
                grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            }
            
            .search-bar input {
                width: 150px;
            }
        }
        
        /* Debug info */
        #debug-info {
            margin-bottom: 10px;
            font-size: 12px;
            overflow-wrap: break-word;
        }

        /* Styles pour le drag & drop */
        .item.file-item {
            cursor: grab;
            transition: transform 0.2s, opacity 0.2s;
            position: relative;
        }

        .item.file-item.dragging {
            opacity: 0.6;
            transform: scale(0.95);
        }

        .item.folder-item {
            position: relative;
        }

        .item.folder-item.drag-over {
            background-color: rgba(79, 70, 229, 0.1);
            border: 2px dashed #4f46e5;
        }

        .drag-message {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 5px;
            z-index: 1000;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .success-message {
            background-color: #10b981;
            color: white;
        }

        .error-message {
            background-color: #ef4444;
            color: white;
        }
        
        /* Search results dropdown */
        .search-results {
            position: absolute;
            top: 100%;
            right: 0;
            width: 300px;
            max-height: 400px;
            overflow-y: auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            z-index: 1000;
            display: none;
        }
        
        .search-results.active {
            display: block;
        }
        
        .search-results-item {
            padding: 10px 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
            transition: background-color 0.2s;
        }
        
        .search-results-item:hover {
            background-color: #f8f9fa;
        }
        
        .search-results-item i {
            font-size: 18px;
            margin-right: 10px;
        }
        
        .search-results-item .result-name {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        /* Shared files section */
        .badge-permission {
            font-size: 11px;
            padding: 3px 6px;
            border-radius: 4px;
            margin-left: 5px;
        }
        
        .badge-read {
            background-color: #e9ecef;
            color: #495057;
        }
        
        .badge-edit {
            background-color: #cfe2ff;
            color: #0a58ca;
        }
        
        .badge-download {
            background-color: #d1e7dd;
            color: #146c43;
        }
        
        .share-list {
            margin: 0;
            padding: 0;
            list-style: none;
            font-size: 12px;
        }
        
        .share-list li {
            margin-bottom: 3px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .share-modal-table {
            width: 100%;
            margin-bottom: 15px;
            font-size: 14px;
        }
        
        .share-modal-table th, 
        .share-modal-table td {
            padding: 8px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .share-modal-table th {
            text-align: left;
            font-weight: 600;
            color: #6c757d;
        }
        
        .expired-share {
            text-decoration: line-through;
            opacity: 0.6;
        }
        
        </style>
</head>
<body>
    <div class="top-bar">
        <div class="logo">
            <img src="logo.png" alt="CloudBOX Logo" height="40">
        </div>
       
        <div class="search-bar">
<input type="text" placeholder="Search files and folders..." class="form-control" id="searchInput" oninput="searchItems()">
<div class="search-results" id="searchResults"></div>
        </div>
    </div>
    
    <nav class="dashboard-nav">
        <a href="home.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
        <a href="drive"><i class="fas fa-folder"></i> My Drive</a>
        <?php if(isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1): ?>
        <a href="admin.php"><i class="fas fa-crown"></i> Admin Panel</a>
        <?php endif; ?>
        <a href="shared.php"><i class="fas fa-share-alt"></i> Shared Files</a>
        <a href="monitoring.php"><i class="fas fa-chart-line"></i> Monitoring</a>
        <a href="settings.php" class="active"><i class="fas fa-cog"></i> Settings</a>

        <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </nav>
    
    <!-- Add Shared Files Tab -->
    <?php if (!empty($shared_files)): ?>
    <div class="alert alert-info mt-3">
        <i class="fas fa-info-circle me-2"></i> You have <strong><?= count($shared_files) ?></strong> files shared with you. 
        <a href="#sharedFilesSection" class="alert-link">View shared files</a>
    </div>
    <?php endif; ?>

    <main>
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3">Welcome, <?= htmlspecialchars($username) ?>!</h1>
        </div>
        
        <!-- Improved Storage Usage Display -->
        <div class="storage-card">
            <div class="storage-header" style="color:black">
                <h2 class="storage-title" style="color:black"><i class="fas fa-hdd me-2"></i> Storage Usage</h2>
                <div class="storage-status">
                    <?php if($usagePercentage > 90): ?>
                        <i class="fas fa-exclamation-triangle me-1"></i> Critical
                    <?php elseif($usagePercentage > 70): ?>
                        <i class="fas fa-exclamation-circle me-1"></i> High
                    <?php else: ?>
                        <i class="fas fa-check-circle me-1"></i> Good
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="storage-progress-container">
                <div class="storage-progress">
                    <div class="storage-progress-text"><?= number_format($usagePercentage, 1) ?>%</div>
                </div>
            </div>
            
            <div class="storage-details">
                <span><i class="fas fa-database me-1"></i> <?= number_format($currentUsage / 1048576, 2) ?> MB used</span>
                <span><i class="fas fa-server me-1"></i> <?= number_format($userQuota / 1048576, 2) ?> MB total</span>
                <span><i class="fas fa-hard-drive me-1"></i> <?= number_format(($userQuota - $currentUsage) / 1048576, 2) ?> MB free</span>
            </div>
        </div>
        
        <!-- Display messages -->
        <?php foreach ($messages as $message): ?>
            <?= $message ?>
        <?php endforeach; ?>
        
        <!-- Breadcrumb navigation -->
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb bg-white p-3 rounded shadow-sm">
                <li class="breadcrumb-item" data-id="root"><a href="home.php"><i class="fas fa-home"></i> Root</a></li>
                <?php foreach ($breadcrumb as $folder): ?>
                    <li class="breadcrumb-item">
                        <a href="home.php?folder_id=<?= $folder['id'] ?>"><?= htmlspecialchars($folder['name']) ?></a>
                    </li>
                <?php endforeach; ?>
                
            </ol>
        </nav>
        
        <div class="row mb-4">
            <!-- Create Folder Form -->
            <div class="col-md-6 mb-3">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title mb-3"><i class="fas fa-folder-plus me-2"></i>Create New Folder</h5>
                        <form method="POST">
                            <div class="input-group mb-3">
                                <input type="text" class="form-control" name="new_folder_name" placeholder="Folder name" required>
                                <button class="btn btn-primary" type="submit">Create</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Upload Files Form -->
            <div class="col-md-6 mb-3">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title mb-3"><i class="fas fa-cloud-upload-alt me-2"></i>Upload Files</h5>
                        
                        <div class="drag-area" id="drag-area">
                            <i class="fas fa-cloud-upload-alt"></i>
                            <p>Drag & drop files here or <strong>click to browse</strong></p>
                            <form method="POST" enctype="multipart/form-data" id="upload-form">
                                <input type="file" name="files[]" id="file-input" multiple class="d-none">
                            </form>
                        </div>
                        
                        <div class="d-flex gap-2 mt-3">
                            <button class="btn btn-primary w-50" onclick="document.getElementById('file-input').click()">
                                <i class="fas fa-file me-1"></i> Select Files
                            </button>
                            <button class="btn btn-success w-50" onclick="selectFolder()">
                                <i class="fas fa-folder me-1"></i> Select Folder
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Folders section -->
        <?php if (!empty($folders)): ?>
        <div class="section-header">
            <i class="fas fa-folder"></i>
            <h2 class="section-title">Folders</h2>
        </div>
        <div class="container-grid">
            <?php foreach ($folders as $folder): ?>
                <div class="item folder-item" data-id="<?= $folder['id'] ?>">
                    <div class="icon folder-icon">
                        <i class="fas fa-folder fa-3x"></i>
                    </div>
                    <div class="name" style="color:black"><?= htmlspecialchars($folder['folder_name']) ?></div>
                    <div class="actions">
                        <a href="home.php?folder_id=<?= $folder['id'] ?>" class="btn btn-sm btn-primary btn-action">
                            <i class="fas fa-folder-open me-1"></i> Open
                        </a>
                        <a href="download_folder.php?folder_id=<?= $folder['id'] ?>" class="btn btn-sm btn-secondary btn-action" title="Download as ZIP">
                            <i class="fas fa-download"></i>
                        </a>
                        <a href="home.php?delete_folder=<?= $folder['id'] ?><?= $current_folder_id ? '&folder_id='.$current_folder_id : '' ?>" 
                           class="btn btn-sm btn-danger btn-action" 
                           onclick="return confirm('Are you sure you want to delete this folder?');">
                            <i class="fas fa-trash"></i>
                        </a>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        
<!-- Files section -->
<?php if (!empty($files)): ?>
<div class="section-header">
    <i class="fas fa-file"></i>
    <h2 class="section-title">Files</h2>
</div>
<div class="container-grid">
    <?php foreach ($files as $file): ?>
        <?php
        // Get file extension
        $extension = strtolower(pathinfo($file['filename'], PATHINFO_EXTENSION));
        
        // Determine file icon based on type or extension
        $iconClass = 'fa-file';
        $isCode = false;
        
        // Code file extensions
        $codeExtensions = ['php', 'py', 'js', 'html', 'css', 'json', 'xml', 'md', 'c', 'cpp', 'h', 
                         'java', 'rb', 'go', 'sh', 'bat', 'ps1', 'sql', 'txt'];
        
        if (in_array($extension, $codeExtensions)) {
            $iconClass = 'fa-file-code';
            $isCode = true;
        } else if (strpos($file['file_type'], 'image/') === 0) {
            $iconClass = 'fa-file-image';
        } else if (strpos($file['file_type'], 'video/') === 0) {
            $iconClass = 'fa-file-video';
        } else if (strpos($file['file_type'], 'audio/') === 0) {
            $iconClass = 'fa-file-audio';
        } else if (strpos($file['file_type'], 'application/pdf') === 0) {
            $iconClass = 'fa-file-pdf';
        } else if (strpos($file['file_type'], 'text/') === 0) {
            $iconClass = 'fa-file-alt';
            $isCode = true;
        } else if (strpos($file['file_type'], 'application/json') === 0 || 
                  strpos($file['file_type'], 'application/xml') === 0 ||
                  strpos($file['file_type'], 'application/javascript') === 0) {
            $iconClass = 'fa-file-code';
            $isCode = true;
        } else if (strpos($file['file_type'], 'application/zip') === 0 || 
                  strpos($file['file_type'], 'application/x-rar') === 0) {
            $iconClass = 'fa-file-archive';
        }
        
        // Check if file is shared
        $isShared = !empty($file['shares']);
        ?>
        <div class="item file-item" draggable="true" data-id="<?= $file['id'] ?>">
            <?php if ($isShared): ?>
            <div class="shared-icon" title="Shared with <?= count($file['shares']) ?> user(s)">
                <i class="fas fa-share-alt"></i>
            </div>
            <?php endif; ?>
            
            <div class="icon file-icon">
                <i class="fas <?= $iconClass ?> fa-3x"></i>
            </div>
            <div class="name" style="color:black"><?= htmlspecialchars(preg_replace('/^(\d+_)+/', '', $file['filename'])) ?></div>
            <div class="file-details"><?= number_format($file['file_size'] / 1024, 2) ?> KB</div>
            <div class="actions">
                <a href="download.php?id=<?= $file['id'] ?>" class="btn btn-sm btn-primary btn-action">
                    <i class="fas fa-download me-1"></i> Download
                </a>
                <a href="#" class="btn btn-sm btn-info btn-action" onclick="previewFile(<?= $file['id'] ?>, true)">
                    <i class="fas fa-eye me-1"></i> Preview
                </a>
                <?php if ($isCode || strpos($file['file_type'], 'text/') === 0): ?>
                <a href="#" class="btn btn-sm btn-warning btn-action" onclick="editFile(<?= $file['id'] ?>)">
                    <i class="fas fa-edit me-1"></i> Edit
                </a>
                <?php endif; ?>
                <a href="#" class="btn btn-sm btn-success btn-action" onclick="openShareModal(<?= $file['id'] ?>, '<?= htmlspecialchars($file['filename']) ?>')">
                    <i class="fas fa-share-alt me-1"></i> Share
                </a>
                <a href="home.php?delete_id=<?= $file['id'] ?><?= $current_folder_id ? '&folder_id='.$current_folder_id : '' ?>" 
                   class="btn btn-sm btn-danger btn-action" 
                   onclick="return confirm('Are you sure you want to delete this file? This will also remove any shares with other users.');">
                    <i class="fas fa-trash"></i>
                </a>
            </div>
            
            <?php if (!empty($file['shares'])): ?>
            <div class="mt-2 w-100">
                <small class="d-block text-center text-muted mb-1">Shared with:</small>
                <ul class="share-list">
                    <?php foreach($file['shares'] as $share): ?>
                        <li>
                            <span title="<?= $share['permission'] ?> access">
                                <i class="fas fa-user me-1"></i> <?= htmlspecialchars($share['username']) ?>
                                <span class="badge badge-permission badge-<?= $share['permission'] ?>"><?= $share['permission'] ?></span>
                            </span>
                            <a href="home.php?stop_sharing=<?= $file['id'] ?>&user_id=<?= $share['shared_with'] ?><?= $current_folder_id ? '&folder_id='.$current_folder_id : '' ?>" 
                               class="text-danger" title="Stop sharing with this user"
                               onclick="return confirm('Stop sharing with <?= htmlspecialchars($share['username']) ?>?');">
                                <i class="fas fa-times"></i>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

        
        <!-- Shared files with current user section -->
        <?php if (!empty($shared_files)): ?>
        <div class="section-header" id="sharedFilesSection">
            <i class="fas fa-share-alt"></i>
            <h2 class="section-title">Files Shared With Me</h2>
        </div>
        <div class="container-grid">
            <?php foreach ($shared_files as $file): ?>
                <?php
                // Get file extension
                $extension = strtolower(pathinfo($file['filename'], PATHINFO_EXTENSION));
                
                // Determine file icon based on type or extension
                $iconClass = 'fa-file';
                $isCode = false;
                
                // Code file extensions
                $codeExtensions = ['php', 'py', 'js', 'html', 'css', 'json', 'xml', 'md', 'c', 'cpp', 'h', 
                                 'java', 'rb', 'go', 'sh', 'bat', 'ps1', 'sql', 'txt'];
                
                if (in_array($extension, $codeExtensions)) {
                    $iconClass = 'fa-file-code';
                    $isCode = true;
                } else if (strpos($file['file_type'], 'image/') === 0) {
                    $iconClass = 'fa-file-image';
                } else if (strpos($file['file_type'], 'video/') === 0) {
                    $iconClass = 'fa-file-video';
                } else if (strpos($file['file_type'], 'audio/') === 0) {
                    $iconClass = 'fa-file-audio';
                } else if (strpos($file['file_type'], 'application/pdf') === 0) {
                    $iconClass = 'fa-file-pdf';
                } else if (strpos($file['file_type'], 'text/') === 0) {
                    $iconClass = 'fa-file-alt';
                    $isCode = true;
                } else if (strpos($file['file_type'], 'application/json') === 0 || 
                          strpos($file['file_type'], 'application/xml') === 0 ||
                          strpos($file['file_type'], 'application/javascript') === 0) {
                    $iconClass = 'fa-file-code';
                    $isCode = true;
                } else if (strpos($file['file_type'], 'application/zip') === 0 || 
                          strpos($file['file_type'], 'application/x-rar') === 0) {
                    $iconClass = 'fa-file-archive';
                }
                
                // Check if share has expired
                $expired = isset($file['expiration_date']) && strtotime($file['expiration_date']) < time();
                ?>
                <div class="item file-item <?= $expired ? 'expired-share' : '' ?>">
                    <div class="shared-icon" title="Shared by <?= htmlspecialchars($file['shared_by']) ?>">
                        <i class="fas fa-user-friends"></i>
                    </div>
                    
                    <div class="icon file-icon">
                        <i class="fas <?= $iconClass ?> fa-3x"></i>
                    </div>
                    <div class="name" style="color:black">
                        <?= htmlspecialchars(preg_replace('/^(\d+_)+/', '', $file['filename'])) ?>
                        <span class="badge badge-permission badge-<?= $file['permission'] ?>"><?= $file['permission'] ?></span>
                    </div>
                    <div class="file-details" style="color:black">
                        <?= number_format($file['file_size'] / 1024, 2) ?> KB
                        <br>
                        <small>Shared by: <?= htmlspecialchars($file['shared_by']) ?></small>
                        <?php if (isset($file['expiration_date'])): ?>
                        <br>
                        <small class="<?= $expired ? 'text-danger' : 'text-muted' ?>">
                            <?= $expired ? 'Expired: ' : 'Expires: ' ?><?= date('Y-m-d', strtotime($file['expiration_date'])) ?>
                        </small>
                        <?php endif; ?>
                    </div>
                    <div class="actions">
                        <?php if (!$expired): ?>
                            <a href="download.php?id=<?= $file['id'] ?>" class="btn btn-sm btn-primary btn-action" 
                               <?= $file['permission'] != 'download' ? 'disabled title="You don\'t have download permission"' : '' ?>>
                                <i class="fas fa-download me-1"></i> Download
                            </a>
                            <a href="#" class="btn btn-sm btn-info btn-action" onclick="previewFile(<?= $file['id'] ?>, true)">
                                <i class="fas fa-eye me-1"></i> Preview
                            </a>
                        <?php else: ?>
                            <div class="text-danger">This share has expired</div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        
        <?php if (empty($folders) && empty($files) && empty($shared_files)): ?>
            <div class="alert alert-info mt-4">
                <i class="fas fa-info-circle me-2"></i> There are no files or folders to display. Upload files or create folders to get started.
            </div>
        <?php endif; ?>
    </main>

    <!-- Modal for file sharing -->
    <div class="modal fade" id="shareModal" tabindex="-1" aria-labelledby="shareModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="shareModalLabel">Share File</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="shareForm" method="POST">
                        <input type="hidden" id="share_file_id" name="share_file_id" value="">
                        
                        <div class="mb-3">
                            <label for="share_filename" class="form-label">File:</label>
                            <input type="text" class="form-control" id="share_filename" readonly>
                        </div>
                        
                        <div class="mb-3">
                            <label for="share_username" class="form-label">Username to share with:</label>
                            <input type="text" class="form-control" id="share_username" name="share_username" required>
                            <div class="form-text">Enter the username of the person you want to share this file with.</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="permission" class="form-label">Permission:</label>
                            <select class="form-select" id="permission" name="permission" required>
                                <option value="read">Read only</option>
                                <option value="edit">Edit</option>
                                <option value="download">Download</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="expiration_date" class="form-label">Expiration Date (optional):</label>
                            <input type="text" class="form-control" id="expiration_date" name="expiration_date" placeholder="Never expires if left empty">
                        </div>
                        
                        <div id="shareCurrentList">
                            <!-- Current shares will be loaded here via JavaScript -->
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" onclick="document.getElementById('shareForm').submit();">Share</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal pour la prévisualisation des fichiers -->
<div class="modal fade" id="previewModal" tabindex="-1" aria-labelledby="previewModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="previewModalLabel">File Preview</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div class="text-center mb-3" id="previewLoader">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-2">Loading file content...</p>
                </div>
                <div id="debug-info" class="alert alert-info mb-3" style="display:none;"></div>
                
                <!-- New container for media content (images, PDFs, Word docs) -->
                <div id="mediaPreviewContainer" class="media-preview-container" style="display:none;"></div>
                
                <!-- Existing text content container -->
                <pre id="fileContent" class="bg-light p-3 rounded" style="max-height: 500px; overflow: auto; display: none;">
                    <code id="codeContent" class="language-none"></code>
                </pre>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" id="downloadPreviewBtn" class="btn btn-primary">Download</a>
            </div>
        </div>
    </div>
</div>
<!-- Modal for file editing -->
<div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="editModalLabel">Edit File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div class="alert alert-info mb-3">
                    <i class="fas fa-keyboard me-1"></i> Keyboard shortcuts: 
                    <span class="badge bg-secondary">Ctrl+S</span> to save, 
                    <span class="badge bg-secondary">Ctrl+/</span> to comment,
                    <span class="badge bg-secondary">F11</span> for fullscreen
                </div>
                <div class="editor-toolbar">
                    <button id="saveFileBtn" class="btn btn-sm btn-success me-2">
                        <i class="fas fa-save me-1"></i> Save
                    </button>
                    <button id="undoBtn" class="btn btn-sm btn-outline-secondary me-2">
                        <i class="fas fa-undo me-1"></i> Undo
                    </button>
                    <button id="redoBtn" class="btn btn-sm btn-outline-secondary me-2">
                        <i class="fas fa-redo me-1"></i> Redo
                    </button>
                    <div class="btn-group ms-3">
                        <button class="btn btn-sm btn-outline-secondary" id="decreaseFontBtn">
                            <i class="fas fa-font"></i>-
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" id="increaseFontBtn">
                            <i class="fas fa-font"></i>+
                        </button>
                    </div>
                </div>
                <textarea id="fileEditor"></textarea>
                <div class="text-muted mt-2 small text-end">
                    <span id="editorStatus"></span>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" id="saveCloseBtn">Save & Close</button>
            </div>
        </div>
    </div>
</div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
    

        // Initialize flatpickr for date selection
        flatpickr("#expiration_date", {
            dateFormat: "Y-m-d",
            minDate: "today"
        });
        
        // File and folder upload handling
        const dragArea = document.getElementById('drag-area');
        const fileInput = document.getElementById('file-input');
        const uploadForm = document.getElementById('upload-form');
        
        // Highlight drag area when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            dragArea.addEventListener(eventName, (e) => {
                e.preventDefault();
                dragArea.classList.add('active');
            });
        });
        
        // Remove highlight when item leaves the drag area
        ['dragleave', 'drop'].forEach(eventName => {
            dragArea.addEventListener(eventName, (e) => {
                e.preventDefault();
                dragArea.classList.remove('active');
            });
        });
        
        // Handle file drop
        dragArea.addEventListener('drop', (e) => {
            e.preventDefault();
            
            // Get files from the drop event
            const files = e.dataTransfer.files;
            
            // Add files to the file input
            if (files.length > 0) {
                fileInput.files = files;
                uploadFiles();
            }
        });
        
        // Handle file selection
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                uploadFiles();
            }
        });
        
        // Function to upload files
        function uploadFiles() {
            // Show loading indicator or message
            const loadingToast = document.createElement('div');
            loadingToast.className = 'alert alert-info';
            loadingToast.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Uploading files, please wait...';
            document.querySelector('main').prepend(loadingToast);
            
            // Submit the form
            uploadForm.submit();
        }
        
        // Function to allow folder selection
        function selectFolder() {
            // Create a temporary input element for folder selection
            const folderInput = document.createElement('input');
            folderInput.type = 'file';
            folderInput.webkitdirectory = true; // For Chrome and Safari
            folderInput.directory = true; // For Firefox
            folderInput.multiple = true; // Multiple files from folder
            
            // Handle folder selection
            folderInput.addEventListener('change', () => {
                if (folderInput.files.length > 0) {
                    // Transfer files to the main file input
                    // This is a workaround since we can't directly set files property
                    const dataTransfer = new DataTransfer();
                    
                    for (let i = 0; i < folderInput.files.length; i++) {
                        dataTransfer.items.add(folderInput.files[i]);
                    }
                    
                    fileInput.files = dataTransfer.files;
                    uploadFiles();
                }
            });
            
            // Trigger folder selection dialog
            folderInput.click();
        }
        
        // Fonction pour prévisualiser les fichiers texte avec coloration syntaxique
   
        
        // Function to open the share modal and populate file info
        function openShareModal(fileId, fileName) {
            document.getElementById('share_file_id').value = fileId;
            document.getElementById('share_filename').value = fileName;
            
            // Get current share information for this file
            fetchShares(fileId);
            
            // Show the modal
            const shareModal = new bootstrap.Modal(document.getElementById('shareModal'));
            shareModal.show();
        }
        
        // Function to fetch current shares for a file
        function fetchShares(fileId) {
            const sharesList = document.getElementById('shareCurrentList');
            sharesList.innerHTML = '<div class="text-center my-3"><div class="spinner-border spinner-border-sm text-secondary" role="status"></div> Loading shares...</div>';
            
            // Fetch the current shares for this file
            fetch(`get_shares.php?file_id=${fileId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.shares.length > 0) {
                        let html = '<div class="mt-4"><h6>Currently shared with:</h6>';
                        html += '<table class="share-modal-table">';
                        html += '<thead><tr><th>User</th><th>Permission</th><th>Expires</th><th></th></tr></thead><tbody>';
                        
                        data.shares.forEach(share => {
                            const expired = share.expiration_date && new Date(share.expiration_date) < new Date();
                            
                            html += `<tr class="${expired ? 'expired-share' : ''}">`;
                            html += `<td>${share.username}</td>`;
                            html += `<td><span class="badge badge-permission badge-${share.permission}">${share.permission}</span></td>`;
                            html += `<td>${share.expiration_date ? (expired ? 'Expired: ' : '') + share.expiration_date : 'Never'}</td>`;
                            html += `<td>
                                      <a href="#" onclick="removeShare(${fileId}, ${share.user_id}); return false;" 
                                         class="text-danger" title="Remove share">
                                        <i class="fas fa-times"></i>
                                      </a>
                                    </td>`;
                            html += '</tr>';
                        });
                        
                        html += '</tbody></table></div>';
                        sharesList.innerHTML = html;
                    } else {
                        sharesList.innerHTML = '<div class="alert alert-info mt-3">This file is not shared with anyone yet.</div>';
                    }
                })
               
        }
        
        // Function to remove a share
        function removeShare(fileId, userId) {
            if (confirm('Are you sure you want to stop sharing this file with this user?')) {
                window.location.href = `home.php?stop_sharing=${fileId}&user_id=${userId}`;
            }
        }

        // Fonctionnalité drag-and-drop pour déplacer des fichiers
        document.addEventListener('DOMContentLoaded', function() {
            // Rendre les fichiers draggable
            const fileItems = document.querySelectorAll('.file-item');
            fileItems.forEach(item => {
                item.addEventListener('dragstart', function(e) {
                    e.dataTransfer.setData('file_id', this.dataset.id);
                    this.classList.add('dragging');
                });
                
                item.addEventListener('dragend', function() {
                    this.classList.remove('dragging');
                });
            });
            
            // Permettre aux dossiers de recevoir les fichiers
            const folderItems = document.querySelectorAll('.folder-item');
            folderItems.forEach(folder => {
                folder.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    this.classList.add('drag-over');
                });
                
                folder.addEventListener('dragleave', function() {
                    this.classList.remove('drag-over');
                });
                
                folder.addEventListener('drop', function(e) {
                    e.preventDefault();
                    this.classList.remove('drag-over');
                    
                    const fileId = e.dataTransfer.getData('file_id');
                    const folderId = this.dataset.id;
                    
                    if (fileId) {
                        moveFile(fileId, folderId);
                    }
                });
            });
            
            // Permettre de déposer les fichiers dans le dossier racine
            const breadcrumbRoot = document.querySelector('.breadcrumb-item[data-id="root"]');
            if (breadcrumbRoot) {
                breadcrumbRoot.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    this.style.backgroundColor = 'rgba(79, 70, 229, 0.1)';
                });
                
                breadcrumbRoot.addEventListener('dragleave', function() {
                    this.style.backgroundColor = '';
                });
                
                breadcrumbRoot.addEventListener('drop', function(e) {
                    e.preventDefault();
                    this.style.backgroundColor = '';
                    
                    const fileId = e.dataTransfer.getData('file_id');
                    if (fileId) {
                        moveFile(fileId, 'root');
                    }
                });
            }
            
            // Function to handle search functionality
 
            
            // Fonction pour déplacer un fichier
            function moveFile(fileId, folderId) {
                const formData = new FormData();
                formData.append('file_id', fileId);
                formData.append('folder_id', folderId);
                
                // Montrer un message de chargement
                const loadingMsg = document.createElement('div');
                loadingMsg.className = 'drag-message';
                loadingMsg.style.backgroundColor = '#4f46e5';
                loadingMsg.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Déplacement en cours...';
                document.body.appendChild(loadingMsg);
                
                fetch('move_file.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    // Supprimer le message de chargement
                    loadingMsg.remove();
                    
                    // Afficher le résultat
                    const message = document.createElement('div');
                    message.className = `drag-message ${data.success ? 'success-message' : 'error-message'}`;
                    message.textContent = data.message;
                    document.body.appendChild(message);
                    
                    // Disparaître après quelques secondes
                    setTimeout(() => {
                        message.remove();
                        if (data.success) {
                            window.location.reload();
                        }
                    }, 1500);
                })
                .catch(error => {
                    // Supprimer le message de chargement
                    loadingMsg.remove();
                    
                    // Afficher l'erreur
                    const message = document.createElement('div');
                    message.className = 'drag-message error-message';
                    message.textContent = 'Erreur lors du déplacement du fichier';
                    document.body.appendChild(message);
                    
                    // Log l'erreur
                    console.error('Error:', error);
                    
                    // Disparaître après quelques secondes
                    setTimeout(() => {
                        message.remove();
                    }, 1500);
                });
            }
        });
        document.addEventListener('DOMContentLoaded', function() {
    const deleteButtons = document.querySelectorAll('a[href*="delete_id"]');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            console.log('Bouton de suppression cliqué : ' + this.href);
            
            // Ne pas commenter cette ligne pour tester en production
            // e.preventDefault(); 
        });
    });
});
    </script>
</body>
</html>
