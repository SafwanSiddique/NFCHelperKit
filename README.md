# NFCHelperKit
The `NFCHelperKit` class in iOS simplifies NFC operations like reading, writing, and securing tags with password protection. It provides single-line methods for complex actions, making NFC integration and usage efficient and user-friendly making it more accesible for developers of all levels. 

UPDATE: I have just added Ease of Access functions (that is what i am going to call the single line functions for now) for setting a password and removing password. Anyways, The code is still very messy but to use this class all you have to do i create a swift file in your project (name it "NFCHelperKit" for consistency and then copy the contents of the NFCHelperKit.swift file from the base folder into that file. Then to use the functions simply call them using:
```swift
NFCHelperKit.shared.lockTagWithoutData(password: "1234") { error in
  if error != nil {
      print(error!)
      //handle incase any error occurs
  }
}
```
OR
```swift
NFCHelperKit.shared.unlockTag(password: "1234") { error in
  if error != nil {
      print(error!)
      //handle incase any error occurs
  }
}
```
TLDR: These are the only function available at this time. I am working on the other parts. The code is very messy. And I have to make a proper readme.


I am currently adding all functionalities that are supported by the iOS CoreNFC Infrastructure. I will soon add the integrated functions like readTag(), writeTag(data), lockTag, addPasswordToTag(password), removePassword(password), eraseTag() etc. Please be patient :)

In the mean while I have uploaded the current version of the code. (It is still very rough and unpolished. But if you need a part of this urgently you can use snippets from the code. //avoid the readTag part for now as it will probably not work as it not dynamic at all right now. Will complete that first.) 

PS. For those interested I will update the repo with an example code and a mini-guide on how ot use this class while I work on a the more comprehensice and complete solution
