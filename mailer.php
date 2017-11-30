<?php
    // My modifications to mailer script from:
    // http://blog.teamtreehouse.com/create-ajax-contact-form
    // Added input sanitizing to prevent injection

    // Only process POST reqeusts.
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        // Get the form fields and remove whitespace.
        $name = strip_tags(trim($_POST["name"]));
		$name = str_replace(array("\r","\n"),array(" "," "),$name);
        $email = filter_var(trim($_POST["email"]), FILTER_SANITIZE_EMAIL);
        $message = trim($_POST["message"]);
        $subject = trim($_POST["subject"]);

        // reCATPCHA Validation.
        $post_data = http_build_query(
            array(
                'secret' => CAPTCHA_SECRET,
                'response' => $_POST['g-recaptcha-response'],
                'remoteip' => $_SERVER['REMOTE_ADDR']
            )
        );
        $opts = array('http' =>
            array(
                'method'  => 'POST',
                'header'  => 'Content-type: application/x-www-form-urlencoded',
                'content' => $post_data
            )
        );
        $context  = stream_context_create($opts);
        $response = file_get_contents('https://www.google.com/recaptcha/api/siteverify', false, $context);
        $result = json_decode($response);

        // Check if you are a robot.
        if(!($result->success)){
            // Set a 400 (bad request) response code and exit.
            http_response_code(400);
            echo "Oops! reCATPCHA dice que eres un robot. Por favor intenta nuevamente.";
            exit;
        }


        // Check that data was sent to the mailer.
        if ( empty($name) OR empty($message) OR empty($subject) OR !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            // Set a 400 (bad request) response code and exit.
            http_response_code(400);
            echo "Oops! Hubo un error en el envío. Por favor, completa el formulario y prueba de nuevo.";
            exit;
        }

        // Set the recipient email address.
        // FIXME: Update this to your desired email address.
        $recipient = "myriam.mena@usm.cl";

        // Build the email content.
        $email_content = "<strong>Nombre:</strong> $name<br />";
        $email_content .= "<strong>Email</strong>: $email<br /><br />";
        $email_content .= "<strong>Mensaje</strong>:<br />$message<br />";

        // Build the email headers.
        $headers = "From: contacto@myriammena.cl\r\n";
        $headers .= "Return-Path: myriam.mena@usm.cl\r\n";
        $headers .= "CC: fjimenez@inf.utfsm.cl\r\n";
        $headers .= "BCC: racacere@alumnos.inf.utfsm.cl\r\n";
        $headers .= 'MIME-Version: 1.0' . "\r\n";
        $headers .= "Content-type: text/html; charset=utf-8\r\n";

        // Send the email.
        if (mail($recipient, $subject, $email_content, $headers)) {
            // Set a 200 (okay) response code.
            http_response_code(200);
            echo "Gracias! Tu mensaje ha sido enviado.";
        } else {
            // Set a 500 (internal server error) response code.
            http_response_code(500);
            echo "Oops! Algo salio mal y no podemos enviar tu mensaje.";
        }

    } else {
        // Not a POST request, set a 403 (forbidden) response code.
        http_response_code(403);
        echo "Hay un error con el envio, por favor intenta nuevamente.";
    }

?>
