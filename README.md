# Configuration

## Example

	$passwordValidatorConfiguration = array(
		'minimumLength' => 8,
		'containsNumber' => true,
		'containsSpecialCharacter' => true,
		'rejectPreviousPasswords' => true,
		'rejectUsernameInPassword' => true,
		'rejectSubstrings' => array('secret','topsecret','open','unlock')
	);
	
	$validator = new KLGPasswordValidator($passwordValidatorConfiguration);
	$validator->setUsername('klaus')->setPassword('secret4me');
	
	if (!$validator->isPasswordValid()) {
		// Handle invalid password:
		$errors = $validator->getErrors();
		$score = $validator->getScore();
	} else {
		// Handle valid password:
		$score = $validator->getScore();
	}
	
## Parameters

### minimumLength

Type: integer

The mimimum length the password must have. If the password is shorter an error is generated:

	PASSWORD_LENGTH:<length needed>.

### containsNumber

Type: boolean or integer

If true, the password must contain 1 number. If an integer (i.e. 3), then the password must contain this number of numbers. Otherwise an error is generated:

	PASSWORD_NOT_ENOUGH_NUMBERS:<count needed>

### containsSpecialCharacter

If true, the password must contain 1 special character. If an integer (i.e. 3), then the password must contain this number of special characters. Otherwise an error is generated:
	PASSWORD_NOT_ENOUGH_SPECIAL_CHARACTERS:<count needed>

### rejectPreviousPasswords



### rejectUsernameInPassword

Type: boolean

If set to true, the username must not be part of the password. If it is, an error is generated:

	PASSWORD_CONTAINS_USERNAME

Please note, that this requires the username to be set by $validator->setUsername($name) before isPasswordValid is called.

### rejectSubstrings

Type: array

Array of substrings not allowed in the password. If one of the substrings is found an error is generated:
	
	PASSWORD_CONTAINS_SUBSTRING:<substring found>

## Live example

Please see the example index.html in the

	example
	
directory. Also the phpUnit test file might be helpful ...

