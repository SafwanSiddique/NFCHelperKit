# NFCHelperKit
The `NFCHelperKit` class in iOS simplifies NFC operations like reading, writing, and securing tags with password protection. It provides single-line methods for complex actions, making NFC integration and usage efficient and user-friendly making it more accesible for developers of all levels. 

UPDATE: I have just added Ease of Access functions (that is what i am going to call the single line functions for now) The inner functionality is still very messy and confusing. (Sorry! But I am working on it. A comprehensive solution coming soon.)
    
## HOW TO USE
Anyways, The code is still very messy but to use this class all you have to do i create a swift file in your project (name it "NFCHelperKit" for consistency and then copy the contents of the NFCHelperKit.swift file from the base folder into that file. Then to use the functions simply call them using:
```swift
NFCHelperKit.shared.<function you need to call>
```

## SUPPORTED FUNCTIONS (so far): 
* Password Protect a Tag
```swift
func passwordProtectTagWithoutData(password: String, completion: @escaping (_ error: String?) -> Void)
```
* Remove password from a password protected tag
```swift
func passwordRemoveTag(password: String, completion: @escaping (_ error: String?) -> Void)
```
* Lock Tag (Permanently)
```swift
func lockTag(completion: @escaping (_ error: String?) -> Void)
```
* Erase contents of the tag
```swift
func eraseTag(completion: @escaping (_ error: String?) -> Void)
```
* Write a Single Url to a Tag
```swift
func writeUrl(urlString: String, completion: @escaping (_ error: String?) -> Void)
```

## FEATURES COMING SOON:
* Write other data types (Text, Contact, Email, Location, Call, Message, Wifi)
* Write Multiple Records to a single Tag
* Comments to easily understand the inner functionality of the code
* Password protect a tag along with data (In one tap)
* A complete readme file
* Multiple variations of each function to cater to each need
    
TLDR: These are the only function available at this time. I am working on the other parts.

I am currently adding all functionalities that are supported by the iOS CoreNFC Infrastructure. I will soon add the integrated functions like readTag(), writeTag(data), lockTag, addPasswordToTag(password), removePassword(password), eraseTag() etc. Please be patient :)

In the mean while I have uploaded the current version of the code. (It is still very rough and unpolished. But if you need a part of this urgently you can use snippets from the code. //avoid the readTag part for now as it will probably not work as it not dynamic at all right now. Will complete that first.) 

PS. For those interested I will update the repo with an example code and a mini-guide on how ot use this class while I work on a the more comprehensice and complete solution
