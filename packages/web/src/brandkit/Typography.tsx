import { Text, View, StyleSheet } from 'react-native'
import { withNamespaces } from 'react-i18next'
import * as React from 'react'
import { colors } from 'src/styles'
import { hashNav } from 'src/shared/menu-items'
import Page from 'src/brandkit/common/Page'

const { brandTypography } = hashNav

export default withNamespaces()(
  React.memo(function Typography() {
    return (
      <Page
        sections={[
          {
            id: brandTypography.overview,
            children: (
              <View style={[styles.container, { height: 900, backgroundColor: colors.lightBlue }]}>
                <Text>overview</Text>
              </View>
            ),
          },
          {
            id: brandTypography.system,
            children: (
              <View
                style={[styles.container, { minHeight: 400, backgroundColor: colors.turquoise }]}
              >
                <Text>{brandTypography.system}</Text>
              </View>
            ),
          },
          {
            id: brandTypography.guideline,
            children: (
              <View style={[styles.container, { height: 500, backgroundColor: colors.deepBlue }]}>
                <Text>guidelines</Text>
              </View>
            ),
          },
        ]}
      />
    )
  })
)

const styles = StyleSheet.create({
  container: { padding: 10 },
})
