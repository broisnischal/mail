package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	gosmtp "github.com/emersion/go-smtp"
)

// Enhanced Backend with better error handling and logging
type EnhancedBackend struct{}

func (bkd *EnhancedBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	remoteAddr := c.Conn().RemoteAddr()
	log.Printf("New SMTP session from %s", remoteAddr)

	return &EnhancedSession{
		RemoteAddr: remoteAddr.String(),
		StartTime:  time.Now(),
	}, nil
}

type EnhancedSession struct {
	From          string
	To            []string
	RemoteAddr    string
	StartTime     time.Time
	Authenticated bool
}

func (s *EnhancedSession) Auth(username, password string) error {
	envUser := os.Getenv("SMTP_USERNAME")
	envPass := os.Getenv("SMTP_PASSWORD")

	if envUser == "" || envPass == "" {
		log.Printf("Authentication attempted but credentials not configured for session from %s", s.RemoteAddr)
		return gosmtp.ErrAuthFailed
	}

	if username == envUser && password == envPass {
		log.Printf("Authentication successful for user '%s' from %s", username, s.RemoteAddr)
		s.Authenticated = true
		return nil
	}

	log.Printf("Authentication failed for user '%s' from %s", username, s.RemoteAddr)
	return gosmtp.ErrAuthFailed
}

func (s *EnhancedSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.From = from
	log.Printf("MAIL FROM: %s (session: %s)", from, s.RemoteAddr)

	// Basic email validation
	if !isValidEmail(from) {
		log.Printf("Invalid sender email format: %s", from)
		return fmt.Errorf("invalid sender email format")
	}

	return nil
}

func (s *EnhancedSession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	// Basic email validation
	if !isValidEmail(to) {
		log.Printf("Invalid recipient email format: %s", to)
		return fmt.Errorf("invalid recipient email format")
	}

	s.To = append(s.To, to)
	log.Printf("RCPT TO: %s (session: %s)", to, s.RemoteAddr)
	return nil
}

func (s *EnhancedSession) Data(r io.Reader) error {
	sessionID := generateSessionID()
	log.Printf("[%s] Receiving email data from %s to %v", sessionID, s.From, s.To)

	emailBytes, err := io.ReadAll(r)
	if err != nil {
		log.Printf("[%s] Failed to read email data: %v", sessionID, err)
		return fmt.Errorf("failed to read email data: %w", err)
	}

	// Add basic headers if missing
	emailContent := string(emailBytes)
	emailContent = s.enhanceEmailHeaders(emailContent, sessionID)
	emailBytes = []byte(emailContent)

	log.Printf("[%s] Processing email (%d bytes) from %s", sessionID, len(emailBytes), s.From)

	// Process each recipient
	successCount := 0
	for _, recipient := range s.To {
		if err := s.relayEmail(recipient, emailBytes, sessionID); err != nil {
			log.Printf("[%s] Failed to deliver to %s: %v", sessionID, recipient, err)
		} else {
			successCount++
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to deliver to any recipients")
	}

	log.Printf("[%s] Successfully delivered to %d/%d recipients", sessionID, successCount, len(s.To))
	return nil
}

func (s *EnhancedSession) enhanceEmailHeaders(content, sessionID string) string {
	lines := strings.Split(content, "\n")

	// Check for required headers
	hasMessageID := false
	hasDate := false

	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "message-id:") {
			hasMessageID = true
		}
		if strings.HasPrefix(strings.ToLower(line), "date:") {
			hasDate = true
		}
	}

	// Add missing headers
	additionalHeaders := []string{}

	if !hasMessageID {
		messageID := fmt.Sprintf("<%s@%s>", sessionID, os.Getenv("SMTP_DOMAIN"))
		additionalHeaders = append(additionalHeaders, "Message-ID: "+messageID)
	}

	if !hasDate {
		additionalHeaders = append(additionalHeaders, "Date: "+time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	}

	// Add server headers
	serverDomain := os.Getenv("SMTP_DOMAIN")
	if serverDomain != "" {
		received := fmt.Sprintf("Received: from %s by %s; %s",
			s.RemoteAddr, serverDomain, time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
		additionalHeaders = append(additionalHeaders, received)
	}

	if len(additionalHeaders) > 0 {
		// Find the end of headers (empty line)
		headerEnd := -1
		for i, line := range lines {
			if strings.TrimSpace(line) == "" {
				headerEnd = i
				break
			}
		}

		if headerEnd >= 0 {
			// Insert additional headers before the empty line
			newLines := append(lines[:headerEnd], additionalHeaders...)
			newLines = append(newLines, lines[headerEnd:]...)
			return strings.Join(newLines, "\n")
		} else {
			// No empty line found, add headers at the beginning
			return strings.Join(additionalHeaders, "\n") + "\n\n" + content
		}
	}

	return content
}

func (s *EnhancedSession) relayEmail(recipient string, emailBytes []byte, sessionID string) error {
	// Extract domain
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address: %s", recipient)
	}
	domain := parts[1]

	// Check if local domain
	serverDomain := os.Getenv("SMTP_DOMAIN")
	if domain == serverDomain {
		return s.handleLocalDelivery(recipient, emailBytes, sessionID)
	}

	// Handle external delivery
	return s.handleExternalDelivery(recipient, domain, emailBytes, sessionID)
}

func (s *EnhancedSession) handleLocalDelivery(recipient string, emailBytes []byte, sessionID string) error {
	log.Printf("[%s] Local delivery for %s", sessionID, recipient)

	// In a real implementation, you would:
	// 1. Store email in local mailbox
	// 2. Check quotas
	// 3. Apply filters
	// 4. Notify user

	// For now, just log and save to file (for testing)
	filename := fmt.Sprintf("/tmp/mail_%s_%s.eml", sessionID, strings.Replace(recipient, "@", "_at_", -1))
	if err := os.WriteFile(filename, emailBytes, 0644); err != nil {
		log.Printf("[%s] Failed to save local mail: %v", sessionID, err)
	} else {
		log.Printf("[%s] Local mail saved to %s", sessionID, filename)
	}

	return nil
}

func (s *EnhancedSession) handleExternalDelivery(recipient, domain string, emailBytes []byte, sessionID string) error {
	// MX lookup with timeout
	log.Printf("[%s] Looking up MX records for %s", sessionID, domain)

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}
	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for %s", domain)
	}

	// Sort by preference
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	// Try each MX server
	var lastErr error
	for _, mx := range mxRecords {
		mxHost := strings.TrimSuffix(mx.Host, ".")
		if err := s.tryMXServer(mxHost, recipient, emailBytes, sessionID); err != nil {
			lastErr = err
			log.Printf("[%s] MX server %s failed: %v", sessionID, mxHost, err)
			continue
		}

		log.Printf("[%s] Successfully delivered to %s via %s", sessionID, recipient, mxHost)
		return nil
	}

	return fmt.Errorf("all MX servers failed, last error: %w", lastErr)
}

func (s *EnhancedSession) tryMXServer(mxHost, recipient string, emailBytes []byte, sessionID string) error {
	// Connect with timeout
	smtpAddr := mxHost + ":25"
	log.Printf("[%s] Connecting to %s", sessionID, smtpAddr)

	conn, err := net.DialTimeout("tcp", smtpAddr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// Create SMTP client
	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer c.Close()

	// Get server capabilities
	if err = c.Hello(os.Getenv("SMTP_DOMAIN")); err != nil {
		return fmt.Errorf("HELO failed: %w", err)
	}

	// Try STARTTLS if available
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName:         mxHost,
			InsecureSkipVerify: false,
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			log.Printf("[%s] STARTTLS failed for %s: %v", sessionID, mxHost, err)
			// Continue without TLS for compatibility
		} else {
			log.Printf("[%s] TLS established with %s", sessionID, mxHost)
		}
	}

	// Send email
	if err = c.Mail(s.From); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err = c.Rcpt(recipient); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	if _, err = wc.Write(emailBytes); err != nil {
		wc.Close()
		return fmt.Errorf("data write failed: %w", err)
	}

	if err = wc.Close(); err != nil {
		return fmt.Errorf("data close failed: %w", err)
	}

	c.Quit()
	return nil
}

func (s *EnhancedSession) Reset() {
	s.From = ""
	s.To = nil
	log.Printf("Session reset for %s", s.RemoteAddr)
}

func (s *EnhancedSession) Logout() error {
	duration := time.Since(s.StartTime)
	log.Printf("Session logout for %s (duration: %v)", s.RemoteAddr, duration)
	return nil
}

// Helper functions
func isValidEmail(email string) bool {
	// Basic email validation
	parts := strings.Split(email, "@")
	return len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 && strings.Contains(parts[1], ".")
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	be := &EnhancedBackend{}
	s := gosmtp.NewServer(be)

	// Server configuration
	port := getEnv("SMTP_PORT", "2525")
	s.Addr = ":" + port

	s.Domain = os.Getenv("SMTP_DOMAIN")
	if s.Domain == "" {
		log.Fatal("SMTP_DOMAIN environment variable is required")
	}

	// Configure limits
	if maxMsgBytes := getEnv("SMTP_MAX_MESSAGE_BYTES", ""); maxMsgBytes != "" {
		if val, err := strconv.ParseInt(maxMsgBytes, 10, 64); err == nil {
			s.MaxMessageBytes = val
		}
	} else {
		s.MaxMessageBytes = 25 * 1024 * 1024 // 25MB default
	}

	if maxRecipients := getEnv("SMTP_MAX_RECIPIENTS", ""); maxRecipients != "" {
		if val, err := strconv.Atoi(maxRecipients); err == nil {
			s.MaxRecipients = val
		}
	} else {
		s.MaxRecipients = 100
	}

	// Configure timeouts
	s.ReadTimeout = 10 * time.Minute
	s.WriteTimeout = 10 * time.Minute

	// TLS Configuration
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		log.Printf("Loading TLS certificates from %s and %s", certFile, keyFile)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS certificates: %v", err)
		}
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		s.AllowInsecureAuth = false
		log.Println("TLS enabled")
	} else {
		log.Println("Warning: Running without TLS (not recommended for production)")
		s.AllowInsecureAuth = true
	}

	// Authentication requirement
	authRequired := getEnv("SMTP_AUTH_REQUIRED", "false")
	if authRequired == "true" {
		log.Println("Authentication required for all sessions")
	}

	log.Printf("Starting SMTP server on %s", s.Addr)
	log.Printf("Domain: %s", s.Domain)
	log.Printf("Max Message Size: %d bytes", s.MaxMessageBytes)
	log.Printf("Max Recipients: %d", s.MaxRecipients)
	log.Printf("Read/Write Timeout: %v", s.ReadTimeout)

	// Create listener
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", s.Addr, err)
	}

	log.Printf("SMTP server ready to accept connections")
	if err := s.Serve(ln); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
