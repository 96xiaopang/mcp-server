package net.portswigger.mcp.security

import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import javax.swing.SwingUtilities
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

enum class HistoryAccessType() {
    HTTP_HISTORY(), WEBSOCKET_HISTORY();
}

interface HistoryAccessApprovalHandler {
    suspend fun requestHistoryAccess(accessType: HistoryAccessType, config: McpConfig): Boolean
}

class SwingHistoryAccessApprovalHandler : HistoryAccessApprovalHandler {
    override suspend fun requestHistoryAccess(
        accessType: HistoryAccessType, config: McpConfig
    ): Boolean {
        return suspendCoroutine { continuation ->
            SwingUtilities.invokeLater {
                val historyTypeName = when (accessType) {
                    HistoryAccessType.HTTP_HISTORY -> "HTTP 历史记录"
                    HistoryAccessType.WEBSOCKET_HISTORY -> "WebSocket 历史记录"
                }

                val message = buildString {
                    appendLine("MCP 客户端请求访问您的 Burp Suite $historyTypeName。")
                    appendLine()
                    appendLine("这可能包含以前 Web 会话的敏感数据。")
                    appendLine("选择您的响应方式：")
                }

                val options = arrayOf(
                    "允许一次", "始终允许 $historyTypeName", "拒绝"
                )

                val burpFrame = findBurpFrame()

                val result = Dialogs.showOptionDialog(
                    burpFrame, message, options
                )

                when (result) {
                    0 -> {
                        continuation.resume(true)
                    }

                    1 -> {
                        when (accessType) {
                            HistoryAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                            HistoryAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                        }
                        continuation.resume(true)
                    }

                    else -> {
                        continuation.resume(false)
                    }
                }
            }
        }
    }
}

object HistoryAccessSecurity {

    var approvalHandler: HistoryAccessApprovalHandler = SwingHistoryAccessApprovalHandler()

    suspend fun checkHistoryAccessPermission(
        accessType: HistoryAccessType, config: McpConfig
    ): Boolean {
        if (!config.requireHistoryAccessApproval) {
            return true
        }

        val isAlwaysAllowed = when (accessType) {
            HistoryAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory
            HistoryAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory
        }

        if (isAlwaysAllowed) {
            return true
        }

        return approvalHandler.requestHistoryAccess(accessType, config)
    }
}