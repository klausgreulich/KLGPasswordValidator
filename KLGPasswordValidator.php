<?php

/*
* Simple configurable password validator
*
* (c) 2012 Klaus L. Greulich <mail@klausgreulich.de>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is furnished
* to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

// Thanks for the strength calculator code by Alix Axel

class KLGPasswordValidator
{

	private $configuration = null;
	private $errors = null;
	private $password = '';
	private $username = '';
	private $score = 0;
	private $passwordDelegate = null;
	
	private $scoreNumberCount = 0;
	private $scoreSpecialCharactersCount = 0;
	private $scoreCharactersCount = 0;
	private $i18n = null;
	
	private $dirty = true;
	
	public function __construct($configuration)
	{
		if (!is_array($configuration)) throw new Exception("Invalid Argument: Password configuration");
		$this->configuration = $configuration;
		$this->errors = array();
	}
	
	public function setUsername($username)
	{
		$this->username = $username;
		$this->dirty = true;
		return $this;
	}
	
	public function setPassword($password)
	{
		$this->password = $password;
		$this->dirty = true;
		return $this;
	}
	
	public function setPasswordDelegate($object)
	{
		$this->dirty = true;
		$this->passwordDelegate = $object;
	}
	
	public function isPasswordValid()
	{
		$this->getErrors();
		return (count($this->errors) == 0);
	}

	public function getErrors()
	{
		if ($this->dirty) $this->validatePassword();
		return $this->errors;
	}
	
	public function getScore()
	{
		if ($this->dirty) $this->validatePassword();
		return $this->score;
	}
	
	private function validatePassword()
	{
		$this->errors = array();
		
		$this->validateLength($this->getConfigData('minimumLength'));
		$this->validateContainsNumber($this->getConfigData('containsNumber'));
		$this->validateContainsSpecialCharacter($this->getConfigData('containsSpecialCharacter'));
		$this->validateCases($this->getConfigData('validateCases'));		
		
		if (isset($this->configuration['rejectPreviousPasswords'])) $this->rejectPreviousPasswords($this->configuration['rejectPreviousPasswords']);
		if (isset($this->configuration['rejectUsernameInPassword'])) $this->validateDoesNotContainUsername($this->configuration['rejectUsernameInPassword']);
		if (isset($this->configuration['rejectSubstrings'])) $this->validateDoesNotHaveSubstrings($this->configuration['rejectSubstrings']);
		if (isset($this->configuration['rejectWordlist'])) $this->validatePasswordIsNotInWordlist($this->configuration['rejectWordlist']);
		if (isset($this->configuration['rejectWordlistSubstring'])) $this->validatePasswordPartIsNotInWordlist($this->configuration['rejectWordlistSubstring']);
		
		$this->checkChunks();
		
		$this->calculateScore();
		
		$this->dirty = false;
	}
	
	private function getConfigData($key)
	{
		if (isset($this->configuration[$key])) return $this->configuration[$key];
		return false;
	}
	
	private function validateLength($length)
	{
		$length = intval($length);
		if ($length == 0) $length = 1;
		
		$passwordLength = strlen(trim($this->password));
		
		$this->score =  $passwordLength * 4;
		
		if ($passwordLength < $length) {
			$this->errors[] = "PASSWORD_LENGTH:$length";
		}
	}
	
	private function rejectPreviousPasswords($validate)
	{
		if ($validate === false) return;
		
		if ($validate === true) {
			if ($this->passwordDelegate == null) {
				throw new InvalidArgumentException("Password delegate is not set");
			}
		
			if (is_callable(array($this->passwordDelegate, 'isPreviousPassword'))) {
				if ($this->passwordDelegate->isPreviousPassword($this->password) == true) {
					$this->errors[] = 'PASSWORD_PREVIOUSLY_USED';
				}
				return;
			} else {
				throw new InvalidArgumentException("Password delegate function isPreviousPassword is not callable");
			}
		}
		
		// @codeCoverageIgnoreStart
		throw new InvalidArgumentException("Invalid parameter for rejectPreviousPasswords: only true or false is allowed");
		// @codeCoverageIgnoreEnd
	}
	
	private function validateContainsNumber($validate)
	{
		if ($validate !== true && $validate !== false && !is_int($validate)) throw new InvalidArgumentException("Invalid parameter for containsNumber: only true or false or an integer is allowed");
		if ($validate === true) {
			$minNumber = 1;
		} else if ($validate === false) {
			$minNumber = 0;
		} else {
			$minNumber = $validate;
		}
		
		preg_match_all('/[0-9]/', $this->password, $result);

        if (!empty($result)) {
            $this->scoreNumberCount = count($result[0]);

            if ($this->scoreNumberCount >= 3) {
                $this->score += 5;
            }
            
        }
        else {
        	// @codeCoverageIgnoreStart
            $this->scoreNumberCount = 0;
            // @codeCoverageIgnoreEnd
        }
        
        if ($this->scoreNumberCount < $minNumber) {
        	$this->errors[] = 'PASSWORD_NOT_ENOUGH_NUMBERS:'.$minNumber;
        }
	}
	
	private function validateContainsSpecialCharacter($validate)
	{
		if ($validate !== true && $validate !== false && !is_int($validate)) throw new InvalidArgumentException("Invalid parameter for containsSpecialCharacter: only true or false or an integer is allowed");
		if ($validate === true) {
			$minNumber = 1;
		} else if ($validate === false) {
			$minNumber = 0;
		} else {
			$minNumber = $validate;
		}
		
		preg_match_all('/[|!@#$%&*\/=?,;.:\-_+~^¨<>()\[\]€{}`\'\\\]/', $this->password, $results);
		
        if (!empty($results)) {
            $this->scoreSpecialCharactersCount = count($results[0]);
			
            if ($this->scoreSpecialCharactersCount >= 2) {
                $this->score += 5;
            }
        } else {
        	// @codeCoverageIgnoreStart
            $this->scoreSpecialCharactersCount = 0;
            // @codeCoverageIgnoreEnd
        }
        
        if ($this->scoreSpecialCharactersCount < $minNumber) {
        	$this->errors[] = 'PASSWORD_NOT_ENOUGH_SPECIAL_CHARACTERS:'.$minNumber;
        }	
	}
	
	private function validateDoesNotContainUsername($validate)
	{
		if ($validate !== true && $validate !== false) throw new InvalidArgumentException("Invalid parameter for rejectUsernameInPassword: only true or false is allowed");
		if ($this->username == '') throw new InvalidArgumentException("Username is unknown");
		
		if ($validate === true) {
			if (strstr(strtolower($this->password),strtolower($this->username)) !== false) {
				$this->errors[] = "PASSWORD_CONTAINS_USERNAME";
			}
		}
		
	}

	private function validateDoesNotHaveSubstrings($words)
	{
		if ($words === false) return;
		
		if (!is_array($words)) throw new InvalidArgumentException("Invalid parameter for rejectSubstrings: array needed");
		
		if (empty($words)) return;
		
		foreach($words as $word) {
			if (strstr(strtolower($this->password),strtolower($word)) !== false) {
				$this->errors[] = "PASSWORD_CONTAINS_SUBSTRING:$word";
			}
		}
	}
	
	private function validateCases($validate) {

        preg_match_all('/[a-z]/', $this->password, $lowercase_characters);
        preg_match_all('/[A-Z]/', $this->password, $uppercase_characters);

        if (!empty($lowercase_characters)) {
            $lowercase_characters = count($lowercase_characters[0]);
        } else {
        	// @codeCoverageIgnoreStart
            $lowercase_characters = 0;
            // @codeCoverageIgnoreEnd
        }

        if (!empty($uppercase_characters)) {
            $uppercase_characters = count($uppercase_characters[0]);
        } else {
        	// @codeCoverageIgnoreStart
            $uppercase_characters = 0;
            // @codeCoverageIgnoreEnd
        }

        if (($lowercase_characters > 0) && ($uppercase_characters > 0)) {
            $this->score += 10;
        }

		$this->scoreCharactersCount = $lowercase_characters + $uppercase_characters;

        if ($validate === true) {
        	if ($lowercase_characters == 0) {
        		$this->errors[] = "PASSWORD_CONTAINS_NO_LOWERCASE";
        	}
        	if ($uppercase_characters == 0) {
        		$this->errors[] = "PASSWORD_CONTAINS_NO_UPPERCASE";
        	}
        }
    }
	
	private function validatePasswordIsNotInWordlist($filePath)
	{
		if (!is_file($filePath)) throw new InvalidArgumentException('Wordlist file not found');
		
		$contents = file_get_contents($filePath);
		$words = explode("\n",$contents);
		
		$password = strtolower($this->password);
		
		if (in_array($password,$words)) {
			$this->errors[] = "PASSWORD_IN_BLACKLIST";
		}
	}
	
	private function validatePasswordPartIsNotInWordlist($filePath)
	{
		if (!is_file($filePath)) throw new InvalidArgumentException('Wordlist file not found');
		
		$contents = file_get_contents($filePath);
		$words = explode("\n",$contents);
		
		$password = strtolower($this->password);
		
		foreach($words as $word) {
			if (strlen($word)>0) {
				if (strstr($password,$word) !== false) {
					if (strlen($word) > 4) {
						$this->errors[] = "PASSWORD_PART_IN_BLACKLIST:$word";
					}
				}
			}
		}
	}
	
	private function checkChunks() {
		$length = strlen($this->password);
        for ($i = 2; $i <= 4; $i++) {
            $temp = str_split($this->password, $i);
            //$this->score -= ( ceil($length / $i) - count(array_unique($temp)));
        }
    }
	
	private function calculateScore()
	{
        if (($this->scoreNumberCount > 0) && ($this->scoreSpecialCharactersCount > 0)) {
            $this->score += 15;
        }

        if (($this->scoreNumberCount > 0) && ($this->scoreCharactersCount > 0)) {
            $this->score += 15;
        }

        if (($this->scoreSpecialCharactersCount > 0) && ($this->scoreCharactersCount > 0)) {
            $this->score += 15;
        }

        if (($this->scoreNumberCount == 0) && ($this->scoreSpecialCharactersCount == 0)) {
            $this->score -= 10;
        }

        if (($this->scoreSpecialCharactersCount == 0) && ($this->scoreCharactersCount == 0)) {
            $this->score -= 10;
        }

        if ($this->score < 0) {
            $this->score = 0;
        }
		
		// @codeCoverageIgnoreStart
        if ($this->score > 100) {
            $this->score = 100;
		}
		// @codeCoverageIgnoreEnd
		
        return $this->score;
    }
	
	public function getHumanReadableErrorMessage($error)
	{
		if ($this->i18n == null) {
			$i18nFileContents = file_get_contents(dirname(__FILE__).'/german.i18n');
			$lines = explode("\n",$i18nFileContents);
			foreach($lines as $line) {
				$e = explode(':',$line);
				if (isset($e[0])&&isset($e[1])) {
					$this->i18n[$e[0]] = $e[1];
				}
			}
		}
		
		$error = explode(':',$error);
		if (isset($error[1])) {		
			return sprintf($this->i18n[$error[0]],$error[1]);
		} else {
			return $this->i18n[$error[0]];
		}
	}
	

}
