// demo.js
require('UIView, UIColor, UILabel')
defineClass('ViewController', {
    // replace the -genView method
    genView: function () {
        var view = self.ORIGgenView();
        
        view.setBackgroundColor(UIColor.greenColor())
        view.setFrame({x: 0, y: 0, width: 100, height: 100})
        var label = UILabel.alloc().initWithFrame(view.frame());
        label.setText("JSPatch");
        label.setTextAlignment(1);
        view.addSubview(label);
        return view;
    }
});
