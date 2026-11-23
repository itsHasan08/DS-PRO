package com.example.domain.engine

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class AxmlPatchOptions(
    val disableDebuggable: Boolean = false,
    val disableBackup: Boolean = false,
    val injectGuardProvider: Boolean = false,
    val enableCoreProtection: Boolean = false,
    val packageName: String = "",
)

data class AxmlPatchResult(
    val manifestBytes: ByteArray,
    val debuggableDisabled: Boolean,
    val backupDisabled: Boolean,
    val guardProviderInjected: Boolean,
    val coreProtectionInjected: Boolean = false,
    val originalAppClass: String = "",
    val originalFactoryClass: String = "",
    val manifestPackageName: String = "",
)

data class AxmlSecuritySummary(
    val packageName: String,
    val isDebuggable: Boolean,
    val allowsBackup: Boolean,
    val hasGuardProvider: Boolean,
    val hasCoreProtection: Boolean,
)

/**
 * Parses and modifies compiled binary AndroidManifest.xml (AXML) chunks directly.
 */
object AxmlManifestPatcher {

    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
    private const val RES_XML_START_NAMESPACE_TYPE = 0x0100
    private const val RES_XML_END_NAMESPACE_TYPE = 0x0101
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val RES_XML_CDATA_TYPE = 0x0104

    private const val UTF8_FLAG = 0x00000100
    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_BOOLEAN = 0x12

    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    const val GUARD_PROVIDER_CLASS = "com.dspro.guard.DsProGuardProvider"
    const val CORE_APP_CLASS = "com.dspro.core.DsProApplication"
    const val CORE_FACTORY_CLASS = "com.dspro.core.DsProComponentFactory"

    private const val ATTR_NAME = 0x01010003
    private const val ATTR_DEBUGGABLE = 0x0101000f
    private const val ATTR_EXPORTED = 0x01010010
    private const val ATTR_AUTHORITIES = 0x01010018
    private const val ATTR_ALLOW_BACKUP = 0x01010280
    private const val ATTR_INIT_ORDER = 0x010103a8
    private const val ATTR_APP_COMPONENT_FACTORY = 0x0101057a

    private data class StyleSpan(
        var nameIdx: Int,
        val firstChar: Int,
        val lastChar: Int,
    )

    private data class AxmlAttribute(
        var nsIdx: Int,
        var nameIdx: Int,
        var rawValueIdx: Int,
        val valueSize: Int,
        val res0: Int,
        var dataType: Int,
        var data: Int,
    )

    private sealed class XmlChunk {
        data class StartNamespace(
            val lineNumber: Int,
            var commentIdx: Int,
            var prefixIdx: Int,
            var uriIdx: Int,
        ) : XmlChunk()

        data class EndNamespace(
            val lineNumber: Int,
            var commentIdx: Int,
            var prefixIdx: Int,
            var uriIdx: Int,
        ) : XmlChunk()

        data class StartElement(
            val lineNumber: Int,
            var commentIdx: Int,
            var nsIdx: Int,
            var nameIdx: Int,
            val attrStart: Int,
            val attrSize: Int,
            var idIndex: Int,
            var classIndex: Int,
            var styleIndex: Int,
            val attributes: MutableList<AxmlAttribute>,
        ) : XmlChunk()

        data class EndElement(
            val lineNumber: Int,
            var commentIdx: Int,
            var nsIdx: Int,
            var nameIdx: Int,
        ) : XmlChunk()

        data class Cdata(
            val lineNumber: Int,
            var commentIdx: Int,
            var dataIdx: Int,
            val valueSize: Int,
            val res0: Int,
            val dataType: Int,
            var data: Int,
        ) : XmlChunk()

        data class RawChunk(
            val bytes: ByteArray,
        ) : XmlChunk()
    }

    private class ParsedAxml(
        val strings: MutableList<String>,
        val styles: MutableList<MutableList<StyleSpan>>,
        val resourceMap: MutableList<Int>,
        val chunks: MutableList<XmlChunk>,
    ) {
        fun shiftStringIndices(fromIndex: Int, delta: Int) {
            if (delta == 0) return
            styles.forEach { spanList ->
                spanList.forEach { span ->
                    if (span.nameIdx >= fromIndex) span.nameIdx += delta
                }
            }
            chunks.forEach { chunk ->
                when (chunk) {
                    is XmlChunk.StartNamespace -> {
                        if (chunk.commentIdx >= fromIndex) chunk.commentIdx += delta
                        if (chunk.prefixIdx >= fromIndex) chunk.prefixIdx += delta
                        if (chunk.uriIdx >= fromIndex) chunk.uriIdx += delta
                    }
                    is XmlChunk.EndNamespace -> {
                        if (chunk.commentIdx >= fromIndex) chunk.commentIdx += delta
                        if (chunk.prefixIdx >= fromIndex) chunk.prefixIdx += delta
                        if (chunk.uriIdx >= fromIndex) chunk.uriIdx += delta
                    }
                    is XmlChunk.StartElement -> {
                        if (chunk.commentIdx >= fromIndex) chunk.commentIdx += delta
                        if (chunk.nsIdx >= fromIndex) chunk.nsIdx += delta
                        if (chunk.nameIdx >= fromIndex) chunk.nameIdx += delta
                        chunk.attributes.forEach { attr ->
                            if (attr.nsIdx >= fromIndex) attr.nsIdx += delta
                            if (attr.nameIdx >= fromIndex) attr.nameIdx += delta
                            if (attr.rawValueIdx >= fromIndex) attr.rawValueIdx += delta
                            if (attr.dataType == TYPE_STRING && attr.data >= fromIndex) attr.data += delta
                        }
                    }
                    is XmlChunk.EndElement -> {
                        if (chunk.commentIdx >= fromIndex) chunk.commentIdx += delta
                        if (chunk.nsIdx >= fromIndex) chunk.nsIdx += delta
                        if (chunk.nameIdx >= fromIndex) chunk.nameIdx += delta
                    }
                    is XmlChunk.Cdata -> {
                        if (chunk.commentIdx >= fromIndex) chunk.commentIdx += delta
                        if (chunk.dataIdx >= fromIndex) chunk.dataIdx += delta
                        if (chunk.dataType == TYPE_STRING && chunk.data >= fromIndex) chunk.data += delta
                    }
                    is XmlChunk.RawChunk -> Unit
                }
            }
        }

        fun ensureResourceAttrString(name: String, resId: Int): Int {
            val existing = resourceMap.indexOf(resId)
            if (existing >= 0) return existing

            val insertIdx = resourceMap.size
            shiftStringIndices(insertIdx, 1)
            strings.add(insertIdx, name)
            if (styles.size > insertIdx) {
                styles.add(insertIdx, mutableListOf())
            }
            resourceMap.add(insertIdx, resId)
            return insertIdx
        }

        fun ensurePlainString(value: String): Int {
            val existing = strings.indexOfFirst { it == value }
            if (existing >= 0) return existing
            strings.add(value)
            return strings.lastIndex
        }
    }

    fun resolvePackageName(axmlBytes: ByteArray): String {
        return runCatching { resolvePackageName(parse(axmlBytes)) }.getOrDefault("")
    }

    fun inspectSecuritySummary(axmlBytes: ByteArray): AxmlSecuritySummary? {
        return runCatching {
            val doc = parse(axmlBytes)
            val pkg = resolvePackageName(doc)
            val app = doc.chunks.filterIsInstance<XmlChunk.StartElement>()
                .firstOrNull { doc.strings.getOrNull(it.nameIdx) == "application" }
            val dbg = app?.attributes?.firstOrNull {
                doc.resourceMap.getOrNull(it.nameIdx) == ATTR_DEBUGGABLE
            }?.let { it.data != 0 } ?: false
            val bkp = app?.attributes?.firstOrNull {
                doc.resourceMap.getOrNull(it.nameIdx) == ATTR_ALLOW_BACKUP
            }?.let { it.data != 0 } ?: true
            val hasGuard = doc.chunks.filterIsInstance<XmlChunk.StartElement>().any { elem ->
                doc.strings.getOrNull(elem.nameIdx) == "provider" &&
                    elem.attributes.any { attr ->
                        doc.resourceMap.getOrNull(attr.nameIdx) == ATTR_NAME &&
                            attr.dataType == TYPE_STRING &&
                            doc.strings.getOrNull(attr.data) == GUARD_PROVIDER_CLASS
                    }
            }
            val appClassAttr = app?.let { getStringAttr(doc, it, ATTR_NAME) }.orEmpty()
            val hasCore = app != null && (
                appClassAttr == CORE_APP_CLASS ||
                    getStringAttr(doc, app, ATTR_APP_COMPONENT_FACTORY) == CORE_FACTORY_CLASS
                )
            AxmlSecuritySummary(
                packageName = pkg,
                isDebuggable = dbg,
                allowsBackup = bkp,
                hasGuardProvider = hasGuard,
                hasCoreProtection = hasCore,
            )
        }.getOrNull()
    }

    fun patch(axmlBytes: ByteArray, options: AxmlPatchOptions): AxmlPatchResult {
        if (!options.disableDebuggable &&
            !options.disableBackup &&
            !options.injectGuardProvider &&
            !options.enableCoreProtection
        ) {
            return AxmlPatchResult(
                manifestBytes = axmlBytes,
                debuggableDisabled = false,
                backupDisabled = false,
                guardProviderInjected = false,
                coreProtectionInjected = false,
                manifestPackageName = resolvePackageName(axmlBytes),
            )
        }

        val doc = parse(axmlBytes)
        val manifestPkg = resolvePackageName(doc).ifBlank { options.packageName }

        val appIdx = doc.chunks.indexOfFirst { chunk ->
            chunk is XmlChunk.StartElement && doc.strings.getOrNull(chunk.nameIdx) == "application"
        }
        require(appIdx >= 0) { "Binary AndroidManifest.xml missing <application> element." }
        val appElem = doc.chunks[appIdx] as XmlChunk.StartElement

        var debuggableDisabled = false
        var backupDisabled = false
        var guardProviderInjected = false
        var coreProtectionInjected = false
        var originalAppClass = ""
        var originalFactoryClass = ""

        if (options.disableDebuggable) {
            val attrNameIdx = doc.ensureResourceAttrString("debuggable", ATTR_DEBUGGABLE)
            val androidNsIdx = ensureAndroidNsIndex(doc)
            setOrInsertBooleanAttr(doc, appElem, androidNsIdx, attrNameIdx, ATTR_DEBUGGABLE, false)
            debuggableDisabled = true
        }

        if (options.disableBackup) {
            val attrNameIdx = doc.ensureResourceAttrString("allowBackup", ATTR_ALLOW_BACKUP)
            val androidNsIdx = ensureAndroidNsIndex(doc)
            setOrInsertBooleanAttr(doc, appElem, androidNsIdx, attrNameIdx, ATTR_ALLOW_BACKUP, false)
            backupDisabled = true
        }

        if (options.enableCoreProtection) {
            val nameAttrIdx = doc.ensureResourceAttrString("name", ATTR_NAME)
            val factoryAttrIdx = doc.ensureResourceAttrString("appComponentFactory", ATTR_APP_COMPONENT_FACTORY)
            val androidNsIdx = ensureAndroidNsIndex(doc)
            val coreAppValIdx = doc.ensurePlainString(CORE_APP_CLASS)
            val coreFactoryValIdx = doc.ensurePlainString(CORE_FACTORY_CLASS)

            val prevAppRaw = getStringAttr(doc, appElem, ATTR_NAME)
            if (prevAppRaw.isNotBlank() && prevAppRaw != CORE_APP_CLASS) {
                originalAppClass = normalizeClassName(prevAppRaw, manifestPkg)
            }
            val prevFactoryRaw = getStringAttr(doc, appElem, ATTR_APP_COMPONENT_FACTORY)
            if (prevFactoryRaw.isNotBlank() && prevFactoryRaw != CORE_FACTORY_CLASS) {
                originalFactoryClass = normalizeClassName(prevFactoryRaw, manifestPkg)
            }

            setOrInsertStringAttr(doc, appElem, androidNsIdx, nameAttrIdx, ATTR_NAME, coreAppValIdx)
            setOrInsertStringAttr(doc, appElem, androidNsIdx, factoryAttrIdx, ATTR_APP_COMPONENT_FACTORY, coreFactoryValIdx)
            coreProtectionInjected = true
        }

        if (options.injectGuardProvider) {
            val alreadyHasProvider = doc.chunks.any { chunk ->
                chunk is XmlChunk.StartElement &&
                    doc.strings.getOrNull(chunk.nameIdx) == "provider" &&
                    chunk.attributes.any { attr ->
                        val attrResId = doc.resourceMap.getOrNull(attr.nameIdx)
                        val attrName = doc.strings.getOrNull(attr.nameIdx)
                        (attrResId == ATTR_NAME || attrName == "name") &&
                            attr.dataType == TYPE_STRING &&
                            doc.strings.getOrNull(attr.data) == GUARD_PROVIDER_CLASS
                    }
            }

            if (!alreadyHasProvider) {
                val pkg = manifestPkg.ifBlank { "app" }
                val nameAttrIdx = doc.ensureResourceAttrString("name", ATTR_NAME)
                val exportedAttrIdx = doc.ensureResourceAttrString("exported", ATTR_EXPORTED)
                val authoritiesAttrIdx = doc.ensureResourceAttrString("authorities", ATTR_AUTHORITIES)
                val initOrderAttrIdx = doc.ensureResourceAttrString("initOrder", ATTR_INIT_ORDER)

                val androidNsIdx = ensureAndroidNsIndex(doc)
                val providerTagIdx = doc.ensurePlainString("provider")
                val classValIdx = doc.ensurePlainString(GUARD_PROVIDER_CLASS)
                val authorityValIdx = doc.ensurePlainString("$pkg.dspro.guard")

                val providerStart = XmlChunk.StartElement(
                    lineNumber = appElem.lineNumber,
                    commentIdx = -1,
                    nsIdx = -1,
                    nameIdx = providerTagIdx,
                    attrStart = 20,
                    attrSize = 20,
                    idIndex = 0,
                    classIndex = 0,
                    styleIndex = 0,
                    attributes = mutableListOf(
                        AxmlAttribute(
                            nsIdx = androidNsIdx,
                            nameIdx = nameAttrIdx,
                            rawValueIdx = classValIdx,
                            valueSize = 8,
                            res0 = 0,
                            dataType = TYPE_STRING,
                            data = classValIdx,
                        ),
                        AxmlAttribute(
                            nsIdx = androidNsIdx,
                            nameIdx = exportedAttrIdx,
                            rawValueIdx = -1,
                            valueSize = 8,
                            res0 = 0,
                            dataType = TYPE_INT_BOOLEAN,
                            data = 0,
                        ),
                        AxmlAttribute(
                            nsIdx = androidNsIdx,
                            nameIdx = authoritiesAttrIdx,
                            rawValueIdx = authorityValIdx,
                            valueSize = 8,
                            res0 = 0,
                            dataType = TYPE_STRING,
                            data = authorityValIdx,
                        ),
                        AxmlAttribute(
                            nsIdx = androidNsIdx,
                            nameIdx = initOrderAttrIdx,
                            rawValueIdx = -1,
                            valueSize = 8,
                            res0 = 0,
                            dataType = TYPE_INT_DEC,
                            data = Int.MAX_VALUE,
                        ),
                    ),
                )
                val providerEnd = XmlChunk.EndElement(
                    lineNumber = appElem.lineNumber,
                    commentIdx = -1,
                    nsIdx = -1,
                    nameIdx = providerTagIdx,
                )

                val currentAppIdx = doc.chunks.indexOf(appElem)
                doc.chunks.add(currentAppIdx + 1, providerEnd)
                doc.chunks.add(currentAppIdx + 1, providerStart)
            }
            guardProviderInjected = true
        }

        return AxmlPatchResult(
            manifestBytes = encode(doc),
            debuggableDisabled = debuggableDisabled,
            backupDisabled = backupDisabled,
            guardProviderInjected = guardProviderInjected,
            coreProtectionInjected = coreProtectionInjected,
            originalAppClass = originalAppClass,
            originalFactoryClass = originalFactoryClass,
            manifestPackageName = manifestPkg,
        )
    }

    fun inspectForTest(axmlBytes: ByteArray): Triple<Boolean?, Boolean?, Boolean> {
        val doc = parse(axmlBytes)
        val app = doc.chunks.filterIsInstance<XmlChunk.StartElement>()
            .firstOrNull { doc.strings.getOrNull(it.nameIdx) == "application" }
        val dbg = app?.attributes?.firstOrNull {
            doc.resourceMap.getOrNull(it.nameIdx) == ATTR_DEBUGGABLE
        }?.let { it.data != 0 }
        val bkp = app?.attributes?.firstOrNull {
            doc.resourceMap.getOrNull(it.nameIdx) == ATTR_ALLOW_BACKUP
        }?.let { it.data != 0 }
        val hasProvider = doc.chunks.filterIsInstance<XmlChunk.StartElement>().any { elem ->
            doc.strings.getOrNull(elem.nameIdx) == "provider" &&
                elem.attributes.any { attr ->
                    doc.resourceMap.getOrNull(attr.nameIdx) == ATTR_NAME &&
                        attr.dataType == TYPE_STRING &&
                        doc.strings.getOrNull(attr.data) == GUARD_PROVIDER_CLASS
                }
        }
        return Triple(dbg, bkp, hasProvider)
    }

    fun inspectCoreForTest(axmlBytes: ByteArray): Pair<String, String> {
        val doc = parse(axmlBytes)
        val app = doc.chunks.filterIsInstance<XmlChunk.StartElement>()
            .firstOrNull { doc.strings.getOrNull(it.nameIdx) == "application" } ?: return "" to ""
        return getStringAttr(doc, app, ATTR_NAME) to getStringAttr(doc, app, ATTR_APP_COMPONENT_FACTORY)
    }

    fun buildMinimalManifestForTest(
        packageName: String,
        debuggable: Boolean? = true,
        allowBackup: Boolean? = true,
    ): ByteArray {
        val strings = mutableListOf(
            "name",
            "debuggable",
            "allowBackup",
            "android",
            ANDROID_NS,
            "manifest",
            "package",
            packageName,
            "application",
        )
        val resMap = mutableListOf(ATTR_NAME, ATTR_DEBUGGABLE, ATTR_ALLOW_BACKUP)
        val appAttrs = mutableListOf<AxmlAttribute>()
        if (debuggable != null) {
            appAttrs += AxmlAttribute(4, 1, -1, 8, 0, TYPE_INT_BOOLEAN, if (debuggable) -1 else 0)
        }
        if (allowBackup != null) {
            appAttrs += AxmlAttribute(4, 2, -1, 8, 0, TYPE_INT_BOOLEAN, if (allowBackup) -1 else 0)
        }
        val chunks = mutableListOf<XmlChunk>(
            XmlChunk.StartNamespace(1, -1, 3, 4),
            XmlChunk.StartElement(
                lineNumber = 2,
                commentIdx = -1,
                nsIdx = -1,
                nameIdx = 5,
                attrStart = 20,
                attrSize = 20,
                idIndex = 0,
                classIndex = 0,
                styleIndex = 0,
                attributes = mutableListOf(
                    AxmlAttribute(-1, 6, 7, 8, 0, TYPE_STRING, 7),
                ),
            ),
            XmlChunk.StartElement(
                lineNumber = 3,
                commentIdx = -1,
                nsIdx = -1,
                nameIdx = 8,
                attrStart = 20,
                attrSize = 20,
                idIndex = 0,
                classIndex = 0,
                styleIndex = 0,
                attributes = appAttrs,
            ),
            XmlChunk.EndElement(3, -1, -1, 8),
            XmlChunk.EndElement(4, -1, -1, 5),
            XmlChunk.EndNamespace(4, -1, 3, 4),
        )
        return encode(ParsedAxml(strings, mutableListOf(), resMap, chunks))
    }

    private fun resolvePackageName(doc: ParsedAxml): String {
        val manifest = doc.chunks.filterIsInstance<XmlChunk.StartElement>()
            .firstOrNull { doc.strings.getOrNull(it.nameIdx) == "manifest" } ?: return ""
        val pkgAttr = manifest.attributes.firstOrNull {
            doc.strings.getOrNull(it.nameIdx) == "package"
        } ?: return ""
        return if (pkgAttr.dataType == TYPE_STRING) doc.strings.getOrNull(pkgAttr.data).orEmpty() else ""
    }

    private fun ensureAndroidNsIndex(doc: ParsedAxml): Int {
        doc.chunks.filterIsInstance<XmlChunk.StartNamespace>().forEach { ns ->
            if (doc.strings.getOrNull(ns.uriIdx) == ANDROID_NS) {
                return ns.uriIdx
            }
        }
        val prefixIdx = doc.ensurePlainString("android")
        val uriIdx = doc.ensurePlainString(ANDROID_NS)
        val manifestStartIdx = doc.chunks.indexOfFirst {
            it is XmlChunk.StartElement && doc.strings.getOrNull(it.nameIdx) == "manifest"
        }.coerceAtLeast(0)
        val manifestEndIdx = doc.chunks.indexOfLast {
            it is XmlChunk.EndElement && doc.strings.getOrNull(it.nameIdx) == "manifest"
        }
        val startLine = (doc.chunks.getOrNull(manifestStartIdx) as? XmlChunk.StartElement)?.lineNumber ?: 1
        val endLine = (doc.chunks.getOrNull(manifestEndIdx) as? XmlChunk.EndElement)?.lineNumber ?: startLine
        doc.chunks.add(
            manifestStartIdx,
            XmlChunk.StartNamespace(lineNumber = startLine, commentIdx = -1, prefixIdx = prefixIdx, uriIdx = uriIdx),
        )
        if (manifestEndIdx >= 0) {
            doc.chunks.add(
                manifestEndIdx + 2,
                XmlChunk.EndNamespace(lineNumber = endLine, commentIdx = -1, prefixIdx = prefixIdx, uriIdx = uriIdx),
            )
        } else {
            doc.chunks.add(
                XmlChunk.EndNamespace(lineNumber = endLine, commentIdx = -1, prefixIdx = prefixIdx, uriIdx = uriIdx),
            )
        }
        return uriIdx
    }

    private fun getStringAttr(
        doc: ParsedAxml,
        element: XmlChunk.StartElement,
        resId: Int,
    ): String {
        val attr = element.attributes.firstOrNull {
            doc.resourceMap.getOrNull(it.nameIdx) == resId
        } ?: return ""
        return if (attr.dataType == TYPE_STRING) doc.strings.getOrNull(attr.data).orEmpty() else ""
    }

    private fun normalizeClassName(rawName: String, packageName: String): String {
        val trimmed = rawName.trim()
        if (trimmed.isEmpty()) return ""
        if (trimmed.startsWith(".")) {
            return if (packageName.isNotEmpty()) "$packageName$trimmed" else trimmed.removePrefix(".")
        }
        if (!trimmed.contains(".") && packageName.isNotEmpty()) {
            return "$packageName.$trimmed"
        }
        return trimmed
    }

    private fun setOrInsertStringAttr(
        doc: ParsedAxml,
        element: XmlChunk.StartElement,
        nsIdx: Int,
        attrNameIdx: Int,
        resId: Int,
        valueStrIdx: Int,
    ) {
        val existing = element.attributes.firstOrNull { attr ->
            attr.nameIdx == attrNameIdx || doc.resourceMap.getOrNull(attr.nameIdx) == resId
        }
        if (existing != null) {
            existing.rawValueIdx = valueStrIdx
            existing.dataType = TYPE_STRING
            existing.data = valueStrIdx
            return
        }

        val idAttr = if (element.idIndex in 1..element.attributes.size) element.attributes[element.idIndex - 1] else null
        val clsAttr = if (element.classIndex in 1..element.attributes.size) element.attributes[element.classIndex - 1] else null
        val styAttr = if (element.styleIndex in 1..element.attributes.size) element.attributes[element.styleIndex - 1] else null

        element.attributes.add(
            AxmlAttribute(
                nsIdx = nsIdx,
                nameIdx = attrNameIdx,
                rawValueIdx = valueStrIdx,
                valueSize = 8,
                res0 = 0,
                dataType = TYPE_STRING,
                data = valueStrIdx,
            ),
        )
        element.attributes.sortBy { attr ->
            doc.resourceMap.getOrNull(attr.nameIdx)?.toLong()?.and(0xFFFFFFFFL) ?: Long.MAX_VALUE
        }
        element.idIndex = idAttr?.let { element.attributes.indexOf(it) + 1 } ?: 0
        element.classIndex = clsAttr?.let { element.attributes.indexOf(it) + 1 } ?: 0
        element.styleIndex = styAttr?.let { element.attributes.indexOf(it) + 1 } ?: 0
    }

    private fun setOrInsertBooleanAttr(
        doc: ParsedAxml,
        element: XmlChunk.StartElement,
        nsIdx: Int,
        attrNameIdx: Int,
        resId: Int,
        value: Boolean,
    ) {
        val intVal = if (value) -1 else 0
        val existing = element.attributes.firstOrNull { attr ->
            attr.nameIdx == attrNameIdx || doc.resourceMap.getOrNull(attr.nameIdx) == resId
        }
        if (existing != null) {
            existing.rawValueIdx = -1
            existing.dataType = TYPE_INT_BOOLEAN
            existing.data = intVal
            return
        }

        val idAttr = if (element.idIndex in 1..element.attributes.size) element.attributes[element.idIndex - 1] else null
        val clsAttr = if (element.classIndex in 1..element.attributes.size) element.attributes[element.classIndex - 1] else null
        val styAttr = if (element.styleIndex in 1..element.attributes.size) element.attributes[element.styleIndex - 1] else null

        element.attributes.add(
            AxmlAttribute(
                nsIdx = nsIdx,
                nameIdx = attrNameIdx,
                rawValueIdx = -1,
                valueSize = 8,
                res0 = 0,
                dataType = TYPE_INT_BOOLEAN,
                data = intVal,
            ),
        )
        element.attributes.sortBy { attr ->
            doc.resourceMap.getOrNull(attr.nameIdx)?.toLong()?.and(0xFFFFFFFFL) ?: Long.MAX_VALUE
        }
        element.idIndex = idAttr?.let { element.attributes.indexOf(it) + 1 } ?: 0
        element.classIndex = clsAttr?.let { element.attributes.indexOf(it) + 1 } ?: 0
        element.styleIndex = styAttr?.let { element.attributes.indexOf(it) + 1 } ?: 0
    }

    private fun parse(bytes: ByteArray): ParsedAxml {
        require(bytes.size >= 8) { "Invalid binary AndroidManifest.xml (too small)." }
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val rootType = buf.getShort(0).toInt() and 0xFFFF
        val rootHeaderSize = buf.getShort(2).toInt() and 0xFFFF
        require(rootType == RES_XML_TYPE) { "Manifest is not binary AXML (header=0x${rootType.toString(16)})." }

        var offset = rootHeaderSize
        var strings = mutableListOf<String>()
        var styles = mutableListOf<MutableList<StyleSpan>>()
        val resourceMap = mutableListOf<Int>()
        val chunks = mutableListOf<XmlChunk>()

        while (offset + 8 <= bytes.size) {
            val type = buf.getShort(offset).toInt() and 0xFFFF
            val headerSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            require(chunkSize >= 8 && offset + chunkSize <= bytes.size) {
                "Corrupt AXML chunk at $offset (size=$chunkSize)."
            }

            when (type) {
                RES_STRING_POOL_TYPE -> {
                    val parsed = parseStringPool(bytes, offset, headerSize)
                    strings = parsed.first
                    styles = parsed.second
                }
                RES_XML_RESOURCE_MAP_TYPE -> {
                    var pos = offset + headerSize
                    while (pos + 4 <= offset + chunkSize) {
                        resourceMap.add(buf.getInt(pos))
                        pos += 4
                    }
                }
                RES_XML_START_NAMESPACE_TYPE -> {
                    chunks += XmlChunk.StartNamespace(
                        lineNumber = buf.getInt(offset + 8),
                        commentIdx = buf.getInt(offset + 12),
                        prefixIdx = buf.getInt(offset + headerSize),
                        uriIdx = buf.getInt(offset + headerSize + 4),
                    )
                }
                RES_XML_END_NAMESPACE_TYPE -> {
                    chunks += XmlChunk.EndNamespace(
                        lineNumber = buf.getInt(offset + 8),
                        commentIdx = buf.getInt(offset + 12),
                        prefixIdx = buf.getInt(offset + headerSize),
                        uriIdx = buf.getInt(offset + headerSize + 4),
                    )
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    val lineNumber = buf.getInt(offset + 8)
                    val commentIdx = buf.getInt(offset + 12)
                    val extOff = offset + headerSize
                    val nsIdx = buf.getInt(extOff)
                    val nameIdx = buf.getInt(extOff + 4)
                    val attrStart = buf.getShort(extOff + 8).toInt() and 0xFFFF
                    val attrSize = buf.getShort(extOff + 10).toInt() and 0xFFFF
                    val attrCount = buf.getShort(extOff + 12).toInt() and 0xFFFF
                    val idIndex = buf.getShort(extOff + 14).toInt() and 0xFFFF
                    val classIndex = buf.getShort(extOff + 16).toInt() and 0xFFFF
                    val styleIndex = buf.getShort(extOff + 18).toInt() and 0xFFFF

                    val attrs = mutableListOf<AxmlAttribute>()
                    var attrOff = extOff + attrStart
                    for (i in 0 until attrCount) {
                        attrs += AxmlAttribute(
                            nsIdx = buf.getInt(attrOff),
                            nameIdx = buf.getInt(attrOff + 4),
                            rawValueIdx = buf.getInt(attrOff + 8),
                            valueSize = buf.getShort(attrOff + 12).toInt() and 0xFFFF,
                            res0 = buf.get(attrOff + 14).toInt() and 0xFF,
                            dataType = buf.get(attrOff + 15).toInt() and 0xFF,
                            data = buf.getInt(attrOff + 16),
                        )
                        attrOff += attrSize
                    }
                    chunks += XmlChunk.StartElement(
                        lineNumber = lineNumber,
                        commentIdx = commentIdx,
                        nsIdx = nsIdx,
                        nameIdx = nameIdx,
                        attrStart = attrStart,
                        attrSize = if (attrSize >= 20) attrSize else 20,
                        idIndex = idIndex,
                        classIndex = classIndex,
                        styleIndex = styleIndex,
                        attributes = attrs,
                    )
                }
                RES_XML_END_ELEMENT_TYPE -> {
                    chunks += XmlChunk.EndElement(
                        lineNumber = buf.getInt(offset + 8),
                        commentIdx = buf.getInt(offset + 12),
                        nsIdx = buf.getInt(offset + headerSize),
                        nameIdx = buf.getInt(offset + headerSize + 4),
                    )
                }
                RES_XML_CDATA_TYPE -> {
                    val extOff = offset + headerSize
                    chunks += XmlChunk.Cdata(
                        lineNumber = buf.getInt(offset + 8),
                        commentIdx = buf.getInt(offset + 12),
                        dataIdx = buf.getInt(extOff),
                        valueSize = buf.getShort(extOff + 4).toInt() and 0xFFFF,
                        res0 = buf.get(extOff + 6).toInt() and 0xFF,
                        dataType = buf.get(extOff + 7).toInt() and 0xFF,
                        data = buf.getInt(extOff + 8),
                    )
                }
                else -> {
                    chunks += XmlChunk.RawChunk(bytes.copyOfRange(offset, offset + chunkSize))
                }
            }

            offset += chunkSize
        }

        return ParsedAxml(strings, styles, resourceMap, chunks)
    }

    private fun parseStringPool(
        bytes: ByteArray,
        offset: Int,
        headerSize: Int,
    ): Pair<MutableList<String>, MutableList<MutableList<StyleSpan>>> {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringCount = buf.getInt(offset + 8)
        val styleCount = buf.getInt(offset + 12)
        val flags = buf.getInt(offset + 16)
        val stringsStart = buf.getInt(offset + 20)
        val stylesStart = buf.getInt(offset + 24)
        val isUtf8 = (flags and UTF8_FLAG) != 0

        val stringOffsets = IntArray(stringCount) { i ->
            buf.getInt(offset + headerSize + i * 4)
        }
        val styleOffsets = IntArray(styleCount) { i ->
            buf.getInt(offset + headerSize + stringCount * 4 + i * 4)
        }

        val strings = MutableList(stringCount) { i ->
            var p = offset + stringsStart + stringOffsets[i]
            if (isUtf8) {
                // skip UTF-16 char length (1 or 2 bytes)
                val b0 = bytes[p++].toInt() and 0xFF
                if ((b0 and 0x80) != 0) p++
                // read UTF-8 byte length (1 or 2 bytes)
                val l0 = bytes[p++].toInt() and 0xFF
                val utf8Len = if ((l0 and 0x80) != 0) {
                    val l1 = bytes[p++].toInt() and 0xFF
                    ((l0 and 0x7F) shl 8) or l1
                } else {
                    l0
                }
                String(bytes, p, utf8Len, Charsets.UTF_8)
            } else {
                val s0 = buf.getShort(p).toInt() and 0xFFFF
                p += 2
                val utf16Len = if ((s0 and 0x8000) != 0) {
                    val s1 = buf.getShort(p).toInt() and 0xFFFF
                    p += 2
                    ((s0 and 0x7FFF) shl 16) or s1
                } else {
                    s0
                }
                String(bytes, p, utf16Len * 2, Charsets.UTF_16LE)
            }
        }

        val styles = MutableList(styleCount) { i ->
            val spans = mutableListOf<StyleSpan>()
            var p = offset + stylesStart + styleOffsets[i]
            while (p + 4 <= bytes.size) {
                val nameIdx = buf.getInt(p)
                if (nameIdx == -1) break
                spans += StyleSpan(
                    nameIdx = nameIdx,
                    firstChar = buf.getInt(p + 4),
                    lastChar = buf.getInt(p + 8),
                )
                p += 12
            }
            spans
        }

        return strings to styles
    }

    private fun encode(doc: ParsedAxml): ByteArray {
        val stringPoolBytes = encodeStringPool(doc.strings, doc.styles)
        val resMapBytes = encodeResourceMap(doc.resourceMap)
        val xmlBodyOut = ByteArrayOutputStream()

        doc.chunks.forEach { chunk ->
            when (chunk) {
                is XmlChunk.StartNamespace -> {
                    val b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                    b.putShort(RES_XML_START_NAMESPACE_TYPE.toShort())
                    b.putShort(16)
                    b.putInt(24)
                    b.putInt(chunk.lineNumber)
                    b.putInt(chunk.commentIdx)
                    b.putInt(chunk.prefixIdx)
                    b.putInt(chunk.uriIdx)
                    xmlBodyOut.write(b.array())
                }
                is XmlChunk.EndNamespace -> {
                    val b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                    b.putShort(RES_XML_END_NAMESPACE_TYPE.toShort())
                    b.putShort(16)
                    b.putInt(24)
                    b.putInt(chunk.lineNumber)
                    b.putInt(chunk.commentIdx)
                    b.putInt(chunk.prefixIdx)
                    b.putInt(chunk.uriIdx)
                    xmlBodyOut.write(b.array())
                }
                is XmlChunk.StartElement -> {
                    val chunkSize = 36 + chunk.attributes.size * 20
                    val b = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
                    b.putShort(RES_XML_START_ELEMENT_TYPE.toShort())
                    b.putShort(16)
                    b.putInt(chunkSize)
                    b.putInt(chunk.lineNumber)
                    b.putInt(chunk.commentIdx)
                    b.putInt(chunk.nsIdx)
                    b.putInt(chunk.nameIdx)
                    b.putShort(20) // attrStart
                    b.putShort(20) // attrSize
                    b.putShort(chunk.attributes.size.toShort())
                    b.putShort(chunk.idIndex.toShort())
                    b.putShort(chunk.classIndex.toShort())
                    b.putShort(chunk.styleIndex.toShort())
                    chunk.attributes.forEach { attr ->
                        b.putInt(attr.nsIdx)
                        b.putInt(attr.nameIdx)
                        b.putInt(attr.rawValueIdx)
                        b.putShort(8)
                        b.put(attr.res0.toByte())
                        b.put(attr.dataType.toByte())
                        b.putInt(attr.data)
                    }
                    xmlBodyOut.write(b.array())
                }
                is XmlChunk.EndElement -> {
                    val b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                    b.putShort(RES_XML_END_ELEMENT_TYPE.toShort())
                    b.putShort(16)
                    b.putInt(24)
                    b.putInt(chunk.lineNumber)
                    b.putInt(chunk.commentIdx)
                    b.putInt(chunk.nsIdx)
                    b.putInt(chunk.nameIdx)
                    xmlBodyOut.write(b.array())
                }
                is XmlChunk.Cdata -> {
                    val b = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN)
                    b.putShort(RES_XML_CDATA_TYPE.toShort())
                    b.putShort(16)
                    b.putInt(28)
                    b.putInt(chunk.lineNumber)
                    b.putInt(chunk.commentIdx)
                    b.putInt(chunk.dataIdx)
                    b.putShort(8)
                    b.put(chunk.res0.toByte())
                    b.put(chunk.dataType.toByte())
                    b.putInt(chunk.data)
                    xmlBodyOut.write(b.array())
                }
                is XmlChunk.RawChunk -> xmlBodyOut.write(chunk.bytes)
            }
        }

        val xmlBody = xmlBodyOut.toByteArray()
        val totalSize = 8 + stringPoolBytes.size + resMapBytes.size + xmlBody.size
        val out = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(RES_XML_TYPE.toShort())
        out.putShort(8)
        out.putInt(totalSize)
        out.put(stringPoolBytes)
        out.put(resMapBytes)
        out.put(xmlBody)
        return out.array()
    }

    private fun encodeStringPool(
        strings: List<String>,
        styles: List<List<StyleSpan>>,
    ): ByteArray {
        val headerSize = 28
        val stringOffsets = IntArray(strings.size)
        val stringData = ByteArrayOutputStream()

        strings.forEachIndexed { i, str ->
            stringOffsets[i] = stringData.size()
            val utf16 = str.toByteArray(Charsets.UTF_16LE)
            val charLen = utf16.size / 2
            if (charLen > 0x7FFF) {
                val hi = ((charLen shr 16) and 0x7FFF) or 0x8000
                val lo = charLen and 0xFFFF
                stringData.write(hi and 0xFF)
                stringData.write((hi shr 8) and 0xFF)
                stringData.write(lo and 0xFF)
                stringData.write((lo shr 8) and 0xFF)
            } else {
                stringData.write(charLen and 0xFF)
                stringData.write((charLen shr 8) and 0xFF)
            }
            stringData.write(utf16)
            stringData.write(0)
            stringData.write(0)
        }
        while (stringData.size() % 4 != 0) {
            stringData.write(0)
        }

        val styleOffsets = IntArray(styles.size)
        val styleData = ByteArrayOutputStream()
        styles.forEachIndexed { i, spanList ->
            styleOffsets[i] = styleData.size()
            val spanBuf = ByteBuffer.allocate(spanList.size * 12 + 4).order(ByteOrder.LITTLE_ENDIAN)
            spanList.forEach { span ->
                spanBuf.putInt(span.nameIdx)
                spanBuf.putInt(span.firstChar)
                spanBuf.putInt(span.lastChar)
            }
            spanBuf.putInt(-1)
            styleData.write(spanBuf.array())
        }
        if (styles.isNotEmpty()) {
            val endMarker = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            endMarker.putInt(-1)
            endMarker.putInt(-1)
            styleData.write(endMarker.array())
        }
        while (styleData.size() % 4 != 0) {
            styleData.write(0)
        }

        val stringBytes = stringData.toByteArray()
        val styleBytes = styleData.toByteArray()
        val stringsStart = headerSize + strings.size * 4 + styles.size * 4
        val stylesStart = if (styles.isEmpty()) 0 else stringsStart + stringBytes.size
        val chunkSize = stringsStart + stringBytes.size + styleBytes.size

        val out = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(RES_STRING_POOL_TYPE.toShort())
        out.putShort(headerSize.toShort())
        out.putInt(chunkSize)
        out.putInt(strings.size)
        out.putInt(styles.size)
        out.putInt(0) // UTF-16LE unsorted
        out.putInt(stringsStart)
        out.putInt(stylesStart)
        stringOffsets.forEach { out.putInt(it) }
        styleOffsets.forEach { out.putInt(it) }
        out.put(stringBytes)
        out.put(styleBytes)
        return out.array()
    }

    private fun encodeResourceMap(resourceMap: List<Int>): ByteArray {
        if (resourceMap.isEmpty()) return ByteArray(0)
        val chunkSize = 8 + resourceMap.size * 4
        val out = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(RES_XML_RESOURCE_MAP_TYPE.toShort())
        out.putShort(8)
        out.putInt(chunkSize)
        resourceMap.forEach { out.putInt(it) }
        return out.array()
    }
}
