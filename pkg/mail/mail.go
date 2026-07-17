package mail

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
)

type EmailTemplate struct {
	Subject  string
	Template string
}

type Mailer struct {
	User string
	Pwd  string
	Host string
	Port string
}

func NewMailer(user, pwd, host, port string) *Mailer {
	return &Mailer{
		User: user,
		Pwd:  pwd,
		Host: host,
		Port: port,
	}
}

type MailerData struct {
	Email string
	Token string
	Url   string
}

var emailTemplates = map[string]EmailTemplate{
	"welcome_template": {
		Subject:  "Welcome to Saccos - Account Activation Required",
		Template: welcome_template,
	},
	"activate_template": {
		Subject:  "Saccos - Account Activation Required",
		Template: activate_template,
	},

	"pwdreset_template": {
		Subject:  "Password Reset Request for Saccos",
		Template: pwdreset_template,
	},
	"completedreset_template": {
		Subject:  "Password Change success for Saccos",
		Template: completedreset_template,
	},


}

func (m *Mailer) SendMail(templateType string, data MailerData) error {
	tmplConfig, ok := emailTemplates[templateType]
	if !ok {
		return fmt.Errorf("unknown template type: %s", templateType)
	}

	tmpl, err := template.New("email").Parse(tmplConfig.Template)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %v", err)
	}

	var emailBody bytes.Buffer
	if err := tmpl.Execute(&emailBody, data); err != nil {
		return fmt.Errorf("failed to execute email template: %v", err)
	}

	recipients := []string{data.Email}

	msg := fmt.Sprintf("Subject: %s\nTo: %s\nContent-Type: text/html\n\n%s", tmplConfig.Subject, data.Email, emailBody.String())

	auth := smtp.PlainAuth("", m.User, m.Pwd, m.Host)
	err = smtp.SendMail(m.Host+":"+m.Port, auth, m.User, recipients, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}
