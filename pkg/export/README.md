# TruffleHog Export Package

`export` 包提供了一个简洁的 API，允许其他 Go 项目将 TruffleHog 的秘密扫描功能作为库来使用。

## 安装

```bash
go get github.com/trufflesecurity/trufflehog/v3/pkg/export
```

## 快速开始

```go
package main

import (
    "fmt"
    "log"

    "github.com/trufflesecurity/trufflehog/v3/pkg/context"
    "github.com/trufflesecurity/trufflehog/v3/pkg/export"
)

func main() {
    // 创建扫描器
    scanner, err := export.NewScanner(
        export.WithVerify(true),  // 启用验证
    )
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    ctx := context.Background()

    // 扫描文件或目录
    output, err := scanner.ScanPath(ctx, "/path/to/scan")
    if err != nil {
        log.Fatal(err)
    }

    // 处理结果
    for _, result := range output.Results {
        fmt.Printf("Found: %s (Verified: %v)\n", result.DetectorName, result.Verified)
    }
}
```

## API 文档

### Scanner 创建选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `WithConcurrency(n int)` | 设置并发工作者数量 | `runtime.NumCPU()` |
| `WithVerify(bool)` | 启用/禁用秘密验证 | `true` |
| `WithIncludeDetectors(string)` | 包含的检测器（逗号分隔） | `"all"` |
| `WithExcludeDetectors(string)` | 排除的检测器（逗号分隔） | `""` |
| `WithFilterEntropy(float64)` | 按香农熵过滤未验证结果 | `0` |
| `WithFilterUnverified(bool)` | 过滤重复的未验证结果 | `false` |

### 扫描方法

#### ScanPath

扫描一个或多个文件或目录：

```go
output, err := scanner.ScanPath(ctx, "/path/to/file", "/path/to/directory")
```

#### ScanPathWithOptions

使用额外选项扫描文件或目录：

```go
output, err := scanner.ScanPathWithOptions(ctx, export.FilesystemOptions{
    Paths:            []string{"/path/to/scan"},
    IncludePathsFile: "/path/to/include-patterns.txt",
    ExcludePathsFile: "/path/to/exclude-patterns.txt",
})
```

#### ScanURLFile

扫描文件中列出的 URL：

```go
output, err := scanner.ScanURLFile(ctx, "/path/to/urls.txt")
```

#### ScanURLs

直接扫描 URL 列表：

```go
output, err := scanner.ScanURLs(ctx, []string{
    "https://example.com/config.yml",
    "https://example.com/secrets.json",
})
```

#### ScanContent

扫描字节内容：

```go
content := []byte("AWS_SECRET_ACCESS_KEY=...")
output, err := scanner.ScanContent(ctx, content)
```

#### ScanString

扫描字符串内容：

```go
output, err := scanner.ScanString(ctx, "GITHUB_TOKEN=ghp_xxx...")
```

#### ScanGit

扫描 Git 仓库：

```go
output, err := scanner.ScanGit(ctx, export.GitOptions{
    URI:         "https://github.com/example/repo.git",
    Branch:      "main",
    SinceCommit: "abc123",
    MaxDepth:    100,
})
```

#### ScanGitRepo

简单扫描 Git 仓库（使用默认选项）：

```go
output, err := scanner.ScanGitRepo(ctx, "https://github.com/example/repo.git")
```

### 结果结构

```go
type ScanResult struct {
    DetectorType      detectorspb.DetectorType  // 检测器类型
    DetectorName      string                     // 检测器名称
    Description       string                     // 描述
    Verified          bool                       // 是否已验证
    VerificationError error                      // 验证错误（如果有）
    Raw               string                     // 原始秘密数据
    RawV2             string                     // 原始秘密标识符
    Redacted          string                     // 脱敏版本
    ExtraData         map[string]string          // 额外数据
    SourceMetadata    *source_metadatapb.MetaData // 源元数据
    SourceType        sourcespb.SourceType       // 源类型
    SourceName        string                     // 源名称
}

type GitOptions struct {
    URI              string  // Git 仓库 URL
    Branch           string  // 要扫描的分支
    SinceCommit      string  // 从此提交开始扫描
    MaxDepth         int     // 最大提交深度
    IncludePathsFile string  // 包含路径模式文件
    ExcludePathsFile string  // 排除路径模式文件
    ExcludeGlobs     string  // 排除的 glob 模式
    Bare             bool    // 是否为裸仓库
}

type ScanMetrics struct {
    BytesScanned           uint64  // 扫描的字节数
    ChunksScanned          uint64  // 扫描的块数
    VerifiedSecretsFound   uint64  // 找到的已验证秘密数
    UnverifiedSecretsFound uint64  // 找到的未验证秘密数
}

type ScanOutput struct {
    Results []ScanResult  // 所有找到的秘密
    Metrics ScanMetrics   // 扫描统计
}
```

## 完整示例

```go
package main

import (
    "fmt"
    "log"

    "github.com/trufflesecurity/trufflehog/v3/pkg/context"
    "github.com/trufflesecurity/trufflehog/v3/pkg/export"
)

func main() {
    // 创建高度配置的扫描器
    scanner, err := export.NewScanner(
        export.WithVerify(true),
        export.WithConcurrency(8),
        export.WithIncludeDetectors("aws,github,gitlab,slack"),
        export.WithFilterEntropy(3.0),
        export.WithFilterUnverified(true),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    ctx := context.Background()

    // 扫描内容
    content := `
    # 配置文件
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    `

    output, err := scanner.ScanString(ctx, content)
    if err != nil {
        log.Fatal(err)
    }

    // 输出结果
    fmt.Printf("扫描完成:\n")
    fmt.Printf("  扫描字节数: %d\n", output.Metrics.BytesScanned)
    fmt.Printf("  已验证秘密: %d\n", output.Metrics.VerifiedSecretsFound)
    fmt.Printf("  未验证秘密: %d\n", output.Metrics.UnverifiedSecretsFound)

    for _, result := range output.Results {
        status := "未验证"
        if result.Verified {
            status = "已验证"
        }
        fmt.Printf("\n[%s] %s (%s)\n", result.DetectorName, result.Redacted, status)
    }
}
```

## 使用场景

1. **CI/CD 集成**: 在构建流程中扫描代码库
2. **安全审计工具**: 集成到安全扫描平台
3. **IDE 插件**: 实时检测代码中的秘密
4. **合规检查**: 自动化合规性验证

## 注意事项

- 扫描大量数据时建议适当调整 `WithConcurrency` 参数
- 生产环境建议启用 `WithVerify(true)` 以减少误报
- 使用 `WithFilterUnverified(true)` 可以减少重复结果
