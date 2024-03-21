//
//  ViewController.swift
//  DemoProject
//
//  Created by Safwan on 12/03/2024.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    @IBAction func onTapButton(_ sender: UIButton) {
        NFCHelperKit.shared.eraseTag { error in
            if error != nil {
                print(error!)
            }
        }
    }
    
    
}

