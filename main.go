package main

import (
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

// MyBackend implements smtp.Backend
type MyBackend struct{}

// NewSession is called by the server to create a new SMTP session.
func (bkd *MyBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	log.Printf("New session from %s", c.Conn().RemoteAddr())
	return &MySession{}, nil
}

// MySession implements smtp.Session
type MySession struct {
	From string
	To   []string
}

// Auth is called by the server to authenticate a client.
func (s *MySession) Auth(username, password string) error {
	envUser := os.Getenv("SMTP_USERNAME")
	envPass := os.Getenv("SMTP_PASSWORD")

	if envUser == "" || envPass == "" {
		log.Println("Warning: SMTP_USERNAME or SMTP_PASSWORD env vars not set. No authentication configured.")
		return gosmtp.ErrAuthFailed
	}

	if username == envUser && password == envPass {
		log.Printf("Authenticated: %s", username)
		return nil
	}
	log.Printf("Authentication failed for: %s", username)
	return gosmtp.ErrAuthFailed
}

// Mail is called by the server to set the sender.
func (s *MySession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.From = from
	log.Printf("Mail FROM: %s", from)
	return nil
}

// Rcpt is called by the server to add a recipient.
func (s *MySession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	s.To = append(s.To, to)
	log.Printf("Rcpt TO: %s", to)
	return nil
}

// Data is called by the server to read the email content.
func (s *MySession) Data(r io.Reader) error {
	log.Printf("Receiving data from %s to %v", s.From, s.To)

	emailBytes, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read email data: %w", err)
	}

	log.Printf("Received email (first 200 chars):\n%s\n...",
		strings.ReplaceAll(string(emailBytes[:min(len(emailBytes), 200)]), "\n", "\\n"))

	// Process each recipient
	for _, recipient := range s.To {
		if err := s.relayEmail(recipient, emailBytes); err != nil {
			log.Printf("Failed to relay email to %s: %v", recipient, err)
			// In production, you'd queue for retry or send bounce message
		}
	}

	return nil
}

// relayEmail handles the actual email relaying to external servers
func (s *MySession) relayEmail(recipient string, emailBytes []byte) error {
	// Extract recipient domain
	_, domain, found := strings.Cut(recipient, "@")
	if !found {
		return fmt.Errorf("invalid recipient address: %s", recipient)
	}

	// Check if this is a local domain (you can customize this logic)
	serverDomain := os.Getenv("SMTP_DOMAIN")
	if domain == serverDomain {
		log.Printf("Local delivery for %s (not implemented - would store in mailbox)", recipient)
		return nil // For now, just log local deliveries
	}

	// Perform MX lookup for external domains
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("failed to lookup MX records for %s: %w", domain, err)
	}
	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for %s", domain)
	}

	// Sort MX records by preference (lower preference = higher priority)
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	// Try each MX server until one works
	var lastErr error
	for _, mx := range mxRecords {
		mxHost := strings.TrimSuffix(mx.Host, ".")
		smtpAddr := mxHost + ":25"

		log.Printf("Attempting to connect to MX server %s for %s", smtpAddr, recipient)

		// Set a reasonable timeout for external connections
		conn, err := net.DialTimeout("tcp", smtpAddr, 30*time.Second)
		if err != nil {
			lastErr = fmt.Errorf("failed to dial MX server %s: %w", smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		// Create SMTP client from the connection
		c, err := smtp.NewClient(conn, mxHost)
		if err != nil {
			conn.Close()
			lastErr = fmt.Errorf("failed to create SMTP client for %s: %w", smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		// Try to start TLS if supported
		if ok, _ := c.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName:         mxHost,
				InsecureSkipVerify: false, // Set to true only for testing
			}
			if err := c.StartTLS(tlsConfig); err != nil {
				log.Printf("Warning: Failed to start TLS with %s: %v", smtpAddr, err)
				// Continue without TLS - some servers allow this
			} else {
				log.Printf("Successfully established TLS connection with %s", smtpAddr)
			}
		}

		// Send the email
		if err = c.Mail(s.From); err != nil {
			c.Close()
			lastErr = fmt.Errorf("failed MAIL FROM for %s on %s: %w", s.From, smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		if err = c.Rcpt(recipient); err != nil {
			c.Close()
			lastErr = fmt.Errorf("failed RCPT TO for %s on %s: %w", recipient, smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		wc, err := c.Data()
		if err != nil {
			c.Close()
			lastErr = fmt.Errorf("failed to get DATA writer for %s: %w", smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		if _, err = wc.Write(emailBytes); err != nil {
			wc.Close()
			c.Close()
			lastErr = fmt.Errorf("failed to write email data for %s: %w", smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		if err = wc.Close(); err != nil {
			c.Close()
			lastErr = fmt.Errorf("failed to close DATA writer for %s: %w", smtpAddr, err)
			log.Print(lastErr)
			continue
		}

		c.Quit()
		c.Close()

		log.Printf("Successfully relayed email for %s to %s via %s", recipient, domain, smtpAddr)
		return nil // Success!
	}

	return fmt.Errorf("failed to relay email after trying all MX servers: %w", lastErr)
}

// Reset is called by the server to reset the session.
func (s *MySession) Reset() {
	s.From = ""
	s.To = nil
	log.Println("Session reset")
}

// Logout is called by the server to terminate the session.
func (s *MySession) Logout() error {
	log.Println("Session logout")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	be := &MyBackend{}
	s := gosmtp.NewServer(be)

	// Configure server using environment variables
	port := getEnv("SMTP_PORT", "2525")
	s.Addr = ":" + port

	s.Domain = os.Getenv("SMTP_DOMAIN")
	if s.Domain == "" {
		log.Fatal("SMTP_DOMAIN environment variable is required.")
	}

	// Configure limits
	if maxMsgBytes := getEnv("SMTP_MAX_MESSAGE_BYTES", ""); maxMsgBytes != "" {
		if val, err := strconv.ParseInt(maxMsgBytes, 10, 64); err == nil {
			s.MaxMessageBytes = val
		}
	} else {
		s.MaxMessageBytes = 10 * 1024 * 1024 // Default to 10MB
	}

	if maxRecipients := getEnv("SMTP_MAX_RECIPIENTS", ""); maxRecipients != "" {
		if val, err := strconv.Atoi(maxRecipients); err == nil {
			s.MaxRecipients = val
		}
	} else {
		s.MaxRecipients = 50
	}

	// Configure timeouts
	if readTimeout := getEnv("SMTP_READ_TIMEOUT", ""); readTimeout != "" {
		if val, err := time.ParseDuration(readTimeout); err == nil {
			s.ReadTimeout = val
		}
	} else {
		s.ReadTimeout = 30 * time.Second
	}

	if writeTimeout := getEnv("SMTP_WRITE_TIMEOUT", ""); writeTimeout != "" {
		if val, err := time.ParseDuration(writeTimeout); err == nil {
			s.WriteTimeout = val
		}
	} else {
		s.WriteTimeout = 30 * time.Second
	}

	// TLS Configuration
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		log.Printf("Loading TLS certificates from %s and %s", certFile, keyFile)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS key pair: %v", err)
		}
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		s.AllowInsecureAuth = false
	} else {
		log.Println("Warning: TLS_CERT_FILE and TLS_KEY_FILE environment variables not set. Running without TLS (unsafe for production).")
		s.AllowInsecureAuth = true
	}

	log.Printf("Starting SMTP server on %s (Domain: %s)", s.Addr, s.Domain)
	log.Printf("Max Message Bytes: %d, Max Recipients: %d", s.MaxMessageBytes, s.MaxRecipients)
	log.Printf("Read Timeout: %s, Write Timeout: %s", s.ReadTimeout, s.WriteTimeout)

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		log.Fatalf("Error listening on %s: %v", s.Addr, err)
	}

	if err := s.Serve(ln); err != nil {
		log.Fatalf("Error serving SMTP: %v", err)
	}
}

// getEnv returns environment variable value or default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
