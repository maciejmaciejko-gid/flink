package org.apache.flink.table.gateway.service.utils;

import org.apache.flink.table.api.internal.TableResultInternal;
import org.apache.flink.table.data.GenericRowData;
import org.apache.flink.table.data.RowData;
import org.apache.flink.table.data.StringData;
import org.apache.flink.table.types.logical.VarCharType;

import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static java.util.regex.Pattern.quote;

public class SensitivePropertiesProtector {

    private static final String SENSITIVE_OPTIONS =
            "[^']*" + String.join("[^']*|[^']*", "user", "pass", quote("sasl.jaas.config")) + "[^']*";

    private static final Pattern CREDENTIALS_PATTERN =
            Pattern.compile(
                    "'(" + SENSITIVE_OPTIONS + ")'\\s*=\\s*'[^']*'", Pattern.CASE_INSENSITIVE);

    private SensitivePropertiesProtector() {}

    public static List<RowData> collectAndProtect(TableResultInternal tableResult) {
        if (tableResult.getResolvedSchema().getColumnCount() != 1) {
            throw new IllegalArgumentException(
                    "Sensitive properties protection not supported for multiple columns");
        }
        if (!(tableResult.getResolvedSchema().getColumnDataTypes().get(0).getLogicalType()
                instanceof VarCharType)) {
            throw new IllegalArgumentException("Operation supported only for text column");
        }
        Spliterator<RowData> spliterator =
                Spliterators.spliteratorUnknownSize(tableResult.collectInternal(), 0);
        return StreamSupport.stream(spliterator, false)
                .map(SensitivePropertiesProtector::protect)
                .collect(Collectors.toList());
    }

    private static RowData protect(RowData rowData) {
        return GenericRowData.ofKind(rowData.getRowKind(), hideSensitive(rowData.getString(0)));
    }

    private static StringData hideSensitive(StringData createStatement) {
        return StringData.fromString(maskCredentials(createStatement.toString()));
    }

    private static String maskCredentials(String ddl) {
        Matcher matcher = CREDENTIALS_PATTERN.matcher(ddl);
        return matcher.replaceAll("'$1' = '****'");
    }
}
