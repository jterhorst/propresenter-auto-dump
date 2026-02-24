# propresenter-auto-dump
An attempt to automatically fetch and dump .proto files from new versions of ProPresenter on a regular cadence.

Inspired by https://github.com/greyshirtguy/ProPresenter7-Proto, we wanted to have something that could automatically pull down the latest version of the app and automatically crack open the binary, extract the proto files, and dump useful code files.
ProPresenter is being iterated upon so quickly now, it would be ideal to have this be an automatic process.

## Swift Package

The generated Swift protobuf types are published as a Swift package. Add it to your project in Xcode or `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/jterhorst/propresenter-auto-dump.git", from: "21.2.0"),
]
```

Then add the dependency to your target:

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "ProPresenterProtos", package: "propresenter-auto-dump"),
    ]
)
```

Import and use the types:

```swift
import ProPresenterProtos

var color = Rv_Data_Color()
color.red = 1.0
color.green = 0.5
color.blue = 0.0
color.alpha = 1.0
```

Supports macOS, iOS, tvOS, watchOS, and Linux.

### TODO:
- [ ] Examples
- [ ] Kotlin generated code?
- [ ] More unit tests for each generated code project
